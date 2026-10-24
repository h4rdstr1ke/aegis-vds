package deployer

import (
	"encoding/json"
	"fmt"
	"strings"

	"aegis-vds/internal/crypto"
	"aegis-vds/internal/sshclient"
)

// DeployConfig options for Sing-box installation
type DeployConfig struct {
	Port      int
	TargetSNI string
	Keys      *crypto.RealityKeyPair
}

// DeploySingBox installs Sing-box, provisions VLESS-Reality config, and activates the service
func DeploySingBox(client *sshclient.Client, cfg DeployConfig) error {
	if cfg.Port == 0 {
		cfg.Port = 443
	}

	// 1. Install or verify Sing-box binary
	installScript := `
if ! command -v sing-box >/dev/null 2>&1; then
    ARCH=$(uname -m)
    case $ARCH in
      x86_64) SBOX_ARCH="amd64" ;;
      aarch64) SBOX_ARCH="arm64" ;;
      *) SBOX_ARCH="amd64" ;;
    esac
    VERSION="1.11.4"
    TAR_FILE="sing-box-${VERSION}-linux-${SBOX_ARCH}.tar.gz"
    URL="https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/${TAR_FILE}"
    
    mkdir -p /tmp/singbox_install
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o /tmp/singbox_install/${TAR_FILE} ${URL}
    else
        wget -q -O /tmp/singbox_install/${TAR_FILE} ${URL}
    fi
    
    tar -xzf /tmp/singbox_install/${TAR_FILE} -C /tmp/singbox_install/
    mv /tmp/singbox_install/sing-box-${VERSION}-linux-${SBOX_ARCH}/sing-box /usr/local/bin/sing-box
    chmod +x /usr/local/bin/sing-box
    rm -rf /tmp/singbox_install
fi
sing-box version
`
	out, err := client.Run(installScript)
	if err != nil {
		return fmt.Errorf("failed to install sing-box binary: %w (%s)", err, out)
	}

	// 2. Generate Sing-box Configuration
	configJSON, err := generateSingBoxJSON(cfg)
	if err != nil {
		return fmt.Errorf("failed to generate JSON config: %w", err)
	}

	// 3. Write configuration to /etc/sing-box/config.json
	err = client.WriteFile("/etc/sing-box/config.json", []byte(configJSON), "0644")
	if err != nil {
		return fmt.Errorf("failed to upload /etc/sing-box/config.json: %w", err)
	}

	// 4. Create systemd unit file
	serviceUnit := `[Unit]
Description=sing-box service (Managed by AegisVDS)
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=5s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
`
	err = client.WriteFile("/etc/systemd/system/sing-box.service", []byte(serviceUnit), "0644")
	if err != nil {
		return fmt.Errorf("failed to create systemd service: %w", err)
	}

	// 5. Open port in firewall & restart service
	fwAndStart := fmt.Sprintf(`
ufw allow %d/tcp 2>/dev/null || true
iptables -I INPUT -p tcp --dport %d -j ACCEPT 2>/dev/null || true
systemctl daemon-reload
systemctl enable sing-box >/dev/null 2>&1
systemctl restart sing-box
sleep 1
systemctl is-active sing-box
`, cfg.Port, cfg.Port)

	status, err := client.Run(fwAndStart)
	if err != nil || !strings.Contains(status, "active") {
		return fmt.Errorf("sing-box service failed to start (status: %s, error: %v)", status, err)
	}

	return nil
}

func generateSingBoxJSON(cfg DeployConfig) (string, error) {
	type userObj struct {
		UUID string `json:"uuid"`
		Flow string `json:"flow"`
	}

	type handshakeObj struct {
		Server     string `json:"server"`
		ServerPort int    `json:"server_port"`
	}

	type realityObj struct {
		Enabled    bool         `json:"enabled"`
		Handshake  handshakeObj `json:"handshake"`
		PrivateKey string       `json:"private_key"`
		ShortID    []string     `json:"short_id"`
	}

	type tlsObj struct {
		Enabled    bool       `json:"enabled"`
		ServerName string     `json:"server_name"`
		Reality    realityObj `json:"reality"`
	}

	type inboundObj struct {
		Type       string    `json:"type"`
		Tag        string    `json:"tag"`
		Listen     string    `json:"listen"`
		ListenPort int       `json:"listen_port"`
		Users      []userObj `json:"users"`
		TLS        tlsObj    `json:"tls"`
	}

	type outboundObj struct {
		Type string `json:"type"`
		Tag  string `json:"tag"`
	}

	type logObj struct {
		Level     string `json:"level"`
		Timestamp bool   `json:"timestamp"`
	}

	type fullConfig struct {
		Log       logObj        `json:"log"`
		Inbounds  []inboundObj  `json:"inbounds"`
		Outbounds []outboundObj `json:"outbounds"`
	}

	c := fullConfig{
		Log: logObj{
			Level:     "warn",
			Timestamp: true,
		},
		Inbounds: []inboundObj{
			{
				Type:       "vless",
				Tag:        "vless-in",
				Listen:     "::",
				ListenPort: cfg.Port,
				Users: []userObj{
					{
						UUID: cfg.Keys.UUID,
						Flow: "xtls-rprx-vision",
					},
				},
				TLS: tlsObj{
					Enabled:    true,
					ServerName: cfg.TargetSNI,
					Reality: realityObj{
						Enabled: true,
						Handshake: handshakeObj{
							Server:     cfg.TargetSNI,
							ServerPort: 443,
						},
						PrivateKey: cfg.Keys.PrivateKey,
						ShortID:    []string{cfg.Keys.ShortID},
					},
				},
			},
		},
		Outbounds: []outboundObj{
			{
				Type: "direct",
				Tag:  "direct",
			},
			{
				Type: "block",
				Tag:  "block",
			},
		},
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
