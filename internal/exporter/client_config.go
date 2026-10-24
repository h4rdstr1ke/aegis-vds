package exporter

import (
	"encoding/json"
	"fmt"
	"os"
)

// GenerateClientJSON creates a client-side Sing-box configuration file
func GenerateClientJSON(p ExportParams, outputPath string) error {
	type serverTlsObj struct {
		Enabled    bool   `json:"enabled"`
		ServerName string `json:"server_name"`
		Reality    struct {
			Enabled   bool   `json:"enabled"`
			PublicKey string `json:"public_key"`
			ShortID   string `json:"short_id"`
		} `json:"reality"`
		Utls struct {
			Enabled     bool   `json:"enabled"`
			Fingerprint string `json:"fingerprint"`
		} `json:"utls"`
	}

	type outboundObj struct {
		Type        string       `json:"type"`
		Tag         string       `json:"tag"`
		Server      string       `json:"server"`
		ServerPort  int          `json:"server_port"`
		UUID        string       `json:"uuid"`
		Flow        string       `json:"flow"`
		TLS         serverTlsObj `json:"tls"`
		PacketAddr  bool         `json:"packet_encoding,omitempty"`
	}

	type clientConfig struct {
		Log struct {
			Level string `json:"level"`
		} `json:"log"`
		Inbounds []map[string]interface{} `json:"inbounds"`
		Outbounds []interface{}           `json:"outbounds"`
	}

	var cfg clientConfig
	cfg.Log.Level = "info"

	// Local socks5/http mixed proxy on port 2080
	cfg.Inbounds = []map[string]interface{}{
		{
			"type":        "mixed",
			"tag":         "mixed-in",
			"listen":      "127.0.0.1",
			"listen_port": 2080,
		},
	}

	out := outboundObj{
		Type:       "vless",
		Tag:        "proxy",
		Server:     p.Host,
		ServerPort: p.Port,
		UUID:       p.Keys.UUID,
		Flow:       "xtls-rprx-vision",
	}
	out.TLS.Enabled = true
	out.TLS.ServerName = p.TargetSNI
	out.TLS.Reality.Enabled = true
	out.TLS.Reality.PublicKey = p.Keys.PublicKey
	out.TLS.Reality.ShortID = p.Keys.ShortID
	out.TLS.Utls.Enabled = true
	out.TLS.Utls.Fingerprint = "chrome"

	cfg.Outbounds = []interface{}{
		out,
		map[string]string{"type": "direct", "tag": "direct"},
		map[string]string{"type": "block", "tag": "block"},
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal client config: %w", err)
	}

	return os.WriteFile(outputPath, data, 0644)
}
