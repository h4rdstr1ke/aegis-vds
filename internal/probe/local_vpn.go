package probe

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// LocalVPNStatus holds full diagnostics of the host's current active VPN connection
type LocalVPNStatus struct {
	IsConnected      bool     `json:"is_connected"`
	Protocol         string   `json:"protocol"`
	InterfaceName    string   `json:"interface_name"`
	TunnelIPv4       string   `json:"tunnel_ipv4"`
	TunnelIPv6       string   `json:"tunnel_ipv6"`
	MTU              int      `json:"mtu"`
	PublicIP         string   `json:"public_ip"`
	Country          string   `json:"country"`
	CountryCode      string   `json:"country_code"`
	City             string   `json:"city"`
	ISP              string   `json:"isp"`
	ASN              string   `json:"asn"`
	DNSResolvers     []string `json:"dns_resolvers"`
	DefaultRoute     string   `json:"default_route"`
	RxBytes          uint64   `json:"rx_bytes"`
	TxBytes          uint64   `json:"tx_bytes"`
	RxPackets        uint64   `json:"rx_packets"`
	TxPackets        uint64   `json:"tx_packets"`
	LatencyMs        int64    `json:"latency_ms"`
	JitterMs         int64    `json:"jitter_ms"`
	PacketLossRate   float64  `json:"packet_loss_rate"`
	ProcessName      string   `json:"process_name"`
	DNSLeakProtected bool     `json:"dns_leak_protected"`
}

// InspectLocalVPN probes the local machine's active network interfaces, routing, public IP, and DNS
func InspectLocalVPN() (*LocalVPNStatus, error) {
	status := &LocalVPNStatus{
		DNSResolvers: []string{},
	}

	// 1. Scan interfaces for active VPN adapter
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			name := strings.ToLower(iface.Name)
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}

			if strings.HasPrefix(name, "amn") ||
				strings.HasPrefix(name, "tun") ||
				strings.HasPrefix(name, "wg") ||
				strings.HasPrefix(name, "tap") ||
				strings.HasPrefix(name, "ppp") ||
				strings.HasPrefix(name, "tailscale") {

				status.IsConnected = true
				status.InterfaceName = iface.Name
				status.MTU = iface.MTU

				if strings.HasPrefix(name, "amn") {
					status.Protocol = "AmneziaWG (AWG)"
				} else if strings.HasPrefix(name, "wg") {
					status.Protocol = "WireGuard"
				} else if strings.HasPrefix(name, "tun") {
					status.Protocol = "TUN Adapter (Sing-box / OpenVPN / Xray)"
				} else {
					status.Protocol = "VPN Tunnel (" + iface.Name + ")"
				}

				// Fetch IPs assigned to this interface
				addrs, _ := iface.Addrs()
				for _, addr := range addrs {
					ipNet, ok := addr.(*net.IPNet)
					if ok && !ipNet.IP.IsLoopback() {
						if ipNet.IP.To4() != nil {
							status.TunnelIPv4 = ipNet.String()
						} else if ipNet.IP.To16() != nil && status.TunnelIPv6 == "" {
							status.TunnelIPv6 = ipNet.String()
						}
					}
				}

				// Read interface stats from sysfs
				readSysfsStats(iface.Name, status)
				break
			}
		}
	}

	// 2. Identify running VPN process
	procOut, err := exec.Command("pgrep", "-a", "-f", "amneziawg-go|sing-box|xray|wireguard|openvpn|clash").Output()
	if err == nil && len(procOut) > 0 {
		line := strings.TrimSpace(strings.Split(string(procOut), "\n")[0])
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			status.ProcessName = filepath.Base(parts[1])
			if !status.IsConnected {
				status.IsConnected = true
				status.Protocol = status.ProcessName
			}
		}
	}

	// 3. Inspect default route to verify tunnel routing
	routeOut, err := exec.Command("ip", "route").Output()
	if err == nil {
		lines := strings.Split(string(routeOut), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "0.0.0.0/1") || strings.HasPrefix(line, "128.0.0.0/1") || (strings.HasPrefix(line, "default") && status.InterfaceName != "" && strings.Contains(line, status.InterfaceName)) {
				status.DefaultRoute = strings.TrimSpace(line)
				status.IsConnected = true
				break
			}
		}
		if status.DefaultRoute == "" && len(lines) > 0 {
			status.DefaultRoute = strings.TrimSpace(lines[0])
		}
	}

	// 4. Retrieve Public IP & Geolocation
	httpClient := &http.Client{Timeout: 3 * time.Second}
	resp, err := httpClient.Get("https://ipinfo.io/json")
	if err == nil {
		defer resp.Body.Close()
		var geo struct {
			IP      string `json:"ip"`
			City    string `json:"city"`
			Country string `json:"country"`
			Org     string `json:"org"`
		}
		if json.NewDecoder(resp.Body).Decode(&geo) == nil {
			status.PublicIP = geo.IP
			status.City = geo.City
			status.Country = geo.Country
			status.CountryCode = geo.Country
			status.ISP = geo.Org
			status.ASN = geo.Org
		}
	}

	// 5. Inspect DNS Resolvers
	if status.InterfaceName != "" {
		dnsOut, err := exec.Command("resolvectl", "dns", status.InterfaceName).Output()
		if err == nil {
			fields := strings.Fields(string(dnsOut))
			for _, f := range fields {
				if net.ParseIP(f) != nil {
					status.DNSResolvers = append(status.DNSResolvers, f)
				}
			}
		}
	}
	if len(status.DNSResolvers) == 0 {
		// Fallback to /etc/resolv.conf
		data, err := os.ReadFile("/etc/resolv.conf")
		if err == nil {
			lines := strings.Split(string(data), "\n")
			for _, l := range lines {
				l = strings.TrimSpace(l)
				if strings.HasPrefix(l, "nameserver") {
					parts := strings.Fields(l)
					if len(parts) >= 2 && net.ParseIP(parts[1]) != nil {
						status.DNSResolvers = append(status.DNSResolvers, parts[1])
					}
				}
			}
		}
	}

	// Check if DNS leak protected (using cloudflare, google, quad9 or private tunnel IP)
	status.DNSLeakProtected = true
	for _, d := range status.DNSResolvers {
		if d == "127.0.0.53" || d == "1.1.1.1" || d == "8.8.8.8" || d == "9.9.9.9" || strings.HasPrefix(d, "10.") || strings.HasPrefix(d, "172.") {
			status.DNSLeakProtected = true
		}
	}

	// 6. Measure Latency & Jitter to 1.1.1.1:53
	lat := MeasureLatency("1.1.1.1", 53, 3)
	if lat != nil {
		status.LatencyMs = lat.AvgRTT.Milliseconds()
		status.JitterMs = lat.Jitter.Milliseconds()
		status.PacketLossRate = lat.LossRate
	}

	return status, nil
}

func readSysfsStats(iface string, s *LocalVPNStatus) {
	base := filepath.Join("/sys/class/net", iface, "statistics")
	if rx, err := os.ReadFile(filepath.Join(base, "rx_bytes")); err == nil {
		s.RxBytes, _ = strconv.ParseUint(strings.TrimSpace(string(rx)), 10, 64)
	}
	if tx, err := os.ReadFile(filepath.Join(base, "tx_bytes")); err == nil {
		s.TxBytes, _ = strconv.ParseUint(strings.TrimSpace(string(tx)), 10, 64)
	}
	if rxp, err := os.ReadFile(filepath.Join(base, "rx_packets")); err == nil {
		s.RxPackets, _ = strconv.ParseUint(strings.TrimSpace(string(rxp)), 10, 64)
	}
	if txp, err := os.ReadFile(filepath.Join(base, "tx_packets")); err == nil {
		s.TxPackets, _ = strconv.ParseUint(strings.TrimSpace(string(txp)), 10, 64)
	}
}
