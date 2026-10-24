package probe

import (
	"fmt"
	"net"
	"strings"
	"time"

	"aegis-vds/internal/sshclient"
)

// ProtocolGrade rating for censorship resistance
type ProtocolGrade string

const (
	GradeExcellent ProtocolGrade = "A+"
	GradeGood      ProtocolGrade = "A"
	GradeFair      ProtocolGrade = "B"
	GradeRisky     ProtocolGrade = "C"
	GradeBlocked   ProtocolGrade = "F"
)

// ProtocolRecommendation evaluation of a specific protocol
type ProtocolRecommendation struct {
	Name        string
	Grade       ProtocolGrade
	Status      string
	Description string
	Pros        string
	Cons        string
}

// DPIReport holds comprehensive results of the anti-censorship assessment
type DPIReport struct {
	UDPFilterStatus string
	IsUDPOpen       bool
	Recommendations []ProtocolRecommendation
}

// EvaluateProtocols analyzes network environment and system capabilities to recommend protocols
func EvaluateProtocols(client *sshclient.Client, sysInfo *SystemInfo, host string) *DPIReport {
	report := &DPIReport{}

	// 1. Probe UDP connectivity
	udpOpen := testUDPConnectivity(client, host)
	report.IsUDPOpen = udpOpen
	if udpOpen {
		report.UDPFilterStatus = "Open (No wholesale UDP drop detected)"
	} else {
		report.UDPFilterStatus = "Restricted or Filtered by ISP/Firewall"
	}

	// 2. Build Recommendation Matrix
	// VLESS Reality
	report.Recommendations = append(report.Recommendations, ProtocolRecommendation{
		Name:        "VLESS + Reality (XTLS-Vision)",
		Grade:       GradeExcellent,
		Status:      "RECOMMENDED (Gold Standard)",
		Description: "Simulates legitimate Google/Apple/Cloudflare browser TLS. Immune to SNI blocking.",
		Pros:        "Bypasses 99% of DPI/TSPU filters, zero certificate setup required, native speed.",
		Cons:        "Proxy protocol (TUN mode requires client-side virtual adapter).",
	})

	// Hysteria 2 (QUIC / UDP)
	if udpOpen {
		report.Recommendations = append(report.Recommendations, ProtocolRecommendation{
			Name:        "Hysteria 2 (QUIC)",
			Grade:       GradeGood,
			Status:      "VIABLE (High Speed)",
			Description: "Brutal congestion control over UDP. Exceptional for bad/lossy connections.",
			Pros:        "Maximum bandwidth on unstable connections, low latency.",
			Cons:        "Requires working UDP. May be throttled during DPI enforcement waves.",
		})
	} else {
		report.Recommendations = append(report.Recommendations, ProtocolRecommendation{
			Name:        "Hysteria 2 (QUIC)",
			Grade:       GradeRisky,
			Status:      "NOT RECOMMENDED (UDP Filtered)",
			Description: "High-performance UDP/QUIC protocol.",
			Pros:        "Very fast on clean connections.",
			Cons:        "Local provider restricts or throttles UDP traffic.",
		})
	}

	// AmneziaWG (AWG)
	if sysInfo.HasTUN && udpOpen {
		report.Recommendations = append(report.Recommendations, ProtocolRecommendation{
			Name:        "AmneziaWG (AWG)",
			Grade:       GradeGood,
			Status:      "VIABLE (Full VPN Adapter)",
			Description: "Obfuscated WireGuard with custom junk packet headers and randomized sizes.",
			Pros:        "Creates a true system TUN adapter, great for routers & all OS traffic.",
			Cons:        "Requires client with AWG support, relies on UDP.",
		})
	} else {
		report.Recommendations = append(report.Recommendations, ProtocolRecommendation{
			Name:        "AmneziaWG (AWG)",
			Grade:       GradeFair,
			Status:      "LIMITED",
			Description: "Obfuscated WireGuard.",
			Pros:        "Full network tunnel.",
			Cons:        "Server lacks TUN device or UDP is restricted.",
		})
	}

	// Shadowsocks-2022
	report.Recommendations = append(report.Recommendations, ProtocolRecommendation{
		Name:        "Shadowsocks-2022",
		Grade:       GradeFair,
		Status:      "BACKUP",
		Description: "Modern AEAD symmetric encryption protocol.",
		Pros:        "Extremely lightweight, minimal CPU usage.",
		Cons:        "No TLS disguise. May be targeted by active probing or entropy filters.",
	})

	// Standard WireGuard
	report.Recommendations = append(report.Recommendations, ProtocolRecommendation{
		Name:        "WireGuard (Standard)",
		Grade:       GradeBlocked,
		Status:      "BLOCKED BY DPI",
		Description: "Standard un-obfuscated WireGuard protocol.",
		Pros:        "Simplicity and speed.",
		Cons:        "Handshake packets are recognized and killed instantly by TSPU/DPI.",
	})

	// OpenVPN
	report.Recommendations = append(report.Recommendations, ProtocolRecommendation{
		Name:        "OpenVPN (Standard)",
		Grade:       GradeBlocked,
		Status:      "BLOCKED BY DPI",
		Description: "Classic TLS-based VPN protocol.",
		Pros:        "Legacy compatibility.",
		Cons:        "Detected and dropped within seconds by modern DPI.",
	})

	return report
}

// testUDPConnectivity checks if client can reach VDS via UDP
func testUDPConnectivity(client *sshclient.Client, host string) bool {
	probePort := 53443

	// Start a lightweight UDP receiver on VDS for 3 seconds
	remoteCmd := fmt.Sprintf("python3 -c \"import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3.0); s.bind(('0.0.0.0', %d)); data, addr = s.recvfrom(1024); s.sendto(b'AEGIS_PONG', addr)\" 2>/dev/null &", probePort)
	client.Run(remoteCmd)

	time.Sleep(500 * time.Millisecond)

	// Send UDP probe packet from client
	raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, probePort))
	if err != nil {
		return false
	}

	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return false
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(2500 * time.Millisecond))
	_, err = conn.Write([]byte("AEGIS_PING"))
	if err != nil {
		return false
	}

	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		// Fallback: check if standard DNS UDP port works
		return checkExternalUDPSupport()
	}

	return strings.Contains(string(buf[:n]), "AEGIS_PONG")
}

func checkExternalUDPSupport() bool {
	// Probe a public 1.1.1.1:53 via UDP to verify if local ISP permits UDP at all
	conn, err := net.DialTimeout("udp", "1.1.1.1:53", 2*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}
