package exporter

import (
	"fmt"
	"net/url"

	"aegis-vds/internal/crypto"
)

// ExportParams holds parameters required to generate client configurations
type ExportParams struct {
	Host      string
	Port      int
	TargetSNI string
	Keys      *crypto.RealityKeyPair
	Remark    string
}

// GenerateVLESSLink formats a standard vless:// link compatible with V2rayN, Hiddify, Sing-box, FoXray, Streisand
func GenerateVLESSLink(p ExportParams) string {
	if p.Port == 0 {
		p.Port = 443
	}
	if p.Remark == "" {
		p.Remark = fmt.Sprintf("AegisVDS-%s", p.Host)
	}

	query := url.Values{}
	query.Set("encryption", "none")
	query.Set("flow", "xtls-rprx-vision")
	query.Set("security", "reality")
	query.Set("sni", p.TargetSNI)
	query.Set("fp", "chrome")
	query.Set("pbk", p.Keys.PublicKey)
	query.Set("sid", p.Keys.ShortID)
	query.Set("type", "tcp")

	return fmt.Sprintf("vless://%s@%s:%d?%s#%s",
		p.Keys.UUID,
		p.Host,
		p.Port,
		query.Encode(),
		url.PathEscape(p.Remark),
	)
}
