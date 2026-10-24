package probe

import (
	"fmt"
	"strings"

	"aegis-vds/internal/sshclient"
)

// SystemInfo holds hardware and OS capabilities of the VDS
type SystemInfo struct {
	OS             string
	Architecture   string
	Kernel         string
	Virtualization string
	RAMTotalMB     string
	DiskFree       string
	HasTUN         bool
	BBRStatus      string
	IsSystemd      bool
}

// InspectSystem gathers all essential system diagnostic metrics from the remote server
func InspectSystem(client *sshclient.Client) (*SystemInfo, error) {
	info := &SystemInfo{}

	// 1. Architecture
	arch, err := client.Run("uname -m")
	if err == nil {
		info.Architecture = arch
	} else {
		info.Architecture = "unknown"
	}

	// 2. Kernel
	kernel, err := client.Run("uname -r")
	if err == nil {
		info.Kernel = kernel
	}

	// 3. OS Identification
	osRelease, err := client.Run(`cat /etc/os-release | grep -E '^(PRETTY_NAME)=' | cut -d= -f2 | tr -d '"'`)
	if err == nil && osRelease != "" {
		info.OS = osRelease
	} else {
		info.OS = "Linux (generic)"
	}

	// 4. Virtualization detection
	virt, err := client.Run("systemd-detect-virt 2>/dev/null || echo unknown")
	if err == nil && virt != "" {
		info.Virtualization = strings.ToUpper(virt)
	} else {
		info.Virtualization = "KVM / Bare-metal"
	}

	// 5. Memory
	mem, err := client.Run(`free -m | awk '/Mem:/ {print $2 " MB (free: " $4 " MB)"}'`)
	if err == nil && mem != "" {
		info.RAMTotalMB = mem
	}

	// 6. Disk Free
	disk, err := client.Run(`df -h / | awk 'NR==2 {print $4 " available (total: " $2 ")"}'`)
	if err == nil && disk != "" {
		info.DiskFree = disk
	}

	// 7. TUN / TAP device support (vital for VPN adapters like WireGuard / Amnezia)
	tun, err := client.Run(`test -c /dev/net/tun && echo "OK" || echo "FAIL"`)
	if err == nil && strings.Contains(tun, "OK") {
		info.HasTUN = true
	} else {
		info.HasTUN = false
	}

	// 8. BBR congestion control status
	bbr, err := client.Run(`sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "cubic"`)
	if err == nil && strings.Contains(bbr, "bbr") {
		info.BBRStatus = "Active (BBR enabled)"
	} else {
		info.BBRStatus = fmt.Sprintf("Standard (%s)", bbr)
	}

	// 9. Init system (systemd)
	initSys, err := client.Run(`ps -p 1 -o comm=`)
	info.IsSystemd = (err == nil && strings.Contains(initSys, "systemd"))

	return info, nil
}
