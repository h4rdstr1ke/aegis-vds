package exporter

import (
	"strings"
	"testing"

	"aegis-vds/internal/crypto"
)

func TestGenerateVLESSLink(t *testing.T) {
	keys := &crypto.RealityKeyPair{
		PrivateKey: "privateKeyExample43CharactersLengthHere1234",
		PublicKey:  "publicKeyExample43CharactersLengthHere12345",
		ShortID:    "0123456789abcdef",
		UUID:       "12345678-1234-4234-8234-1234567890ab",
	}

	p := ExportParams{
		Host:      "198.51.100.1",
		Port:      443,
		TargetSNI: "dl.google.com",
		Keys:      keys,
		Remark:    "MyVDS",
	}

	link := GenerateVLESSLink(p)

	if !strings.HasPrefix(link, "vless://12345678-1234-4234-8234-1234567890ab@198.51.100.1:443?") {
		t.Errorf("Unexpected link format: %s", link)
	}

	if !strings.Contains(link, "security=reality") {
		t.Errorf("Missing security=reality in link: %s", link)
	}
	if !strings.Contains(link, "flow=xtls-rprx-vision") {
		t.Errorf("Missing flow=xtls-rprx-vision in link: %s", link)
	}
	if !strings.Contains(link, "sni=dl.google.com") {
		t.Errorf("Missing sni in link: %s", link)
	}
	if !strings.Contains(link, "pbk=publicKeyExample43CharactersLengthHere12345") {
		t.Errorf("Missing public key in link: %s", link)
	}
	if !strings.Contains(link, "sid=0123456789abcdef") {
		t.Errorf("Missing short ID in link: %s", link)
	}
	if !strings.HasSuffix(link, "#MyVDS") {
		t.Errorf("Missing remark in link: %s", link)
	}
}
