package deployer

import (
	"strings"

	"aegis-vds/internal/sshclient"
)

// EnableBBR configures Google BBR TCP congestion control on the remote server
func EnableBBR(client *sshclient.Client) (bool, error) {
	// Check current status
	status, err := client.Run("sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true")
	if err == nil && strings.TrimSpace(status) == "bbr" {
		return true, nil
	}

	// Apply BBR
	cmds := `
modprobe tcp_bbr 2>/dev/null || true
echo "tcp_bbr" >> /etc/modules-load.d/bbr.conf 2>/dev/null || true
sysctl -w net.core.default_qdisc=fq
sysctl -w net.ipv4.tcp_congestion_control=bbr
grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf || echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf || echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p >/dev/null 2>&1 || true
`
	_, err = client.Run(cmds)
	if err != nil {
		return false, err
	}

	check, _ := client.Run("sysctl -n net.ipv4.tcp_congestion_control")
	return strings.TrimSpace(check) == "bbr", nil
}
