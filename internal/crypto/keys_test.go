package crypto

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestGenerateRealityKeys(t *testing.T) {
	keys, err := GenerateRealityKeys()
	if err != nil {
		t.Fatalf("GenerateRealityKeys failed: %v", err)
	}

	if keys.PrivateKey == "" {
		t.Errorf("PrivateKey is empty")
	}
	if keys.PublicKey == "" {
		t.Errorf("PublicKey is empty")
	}
	if len(keys.ShortID) != 16 {
		t.Errorf("Expected ShortID length 16, got %d (%s)", len(keys.ShortID), keys.ShortID)
	}
	if len(keys.UUID) != 36 {
		t.Errorf("Expected UUID length 36, got %d (%s)", len(keys.UUID), keys.UUID)
	}

	// Validate base64 raw URL encoding (32 bytes = 43 chars in unpadded base64)
	if len(keys.PrivateKey) != 43 {
		t.Errorf("Expected raw base64 private key length 43, got %d (%s)", len(keys.PrivateKey), keys.PrivateKey)
	}
	if len(keys.PublicKey) != 43 {
		t.Errorf("Expected raw base64 public key length 43, got %d (%s)", len(keys.PublicKey), keys.PublicKey)
	}

	// Verify decoding
	privRaw, err := base64.RawURLEncoding.DecodeString(keys.PrivateKey)
	if err != nil || len(privRaw) != 32 {
		t.Errorf("Failed to decode private key to 32 bytes: %v", err)
	}

	pubRaw, err := base64.RawURLEncoding.DecodeString(keys.PublicKey)
	if err != nil || len(pubRaw) != 32 {
		t.Errorf("Failed to decode public key to 32 bytes: %v", err)
	}

	// Verify UUID format (8-4-4-4-12)
	parts := strings.Split(keys.UUID, "-")
	if len(parts) != 5 {
		t.Errorf("Invalid UUID format: %s", keys.UUID)
	}
}
