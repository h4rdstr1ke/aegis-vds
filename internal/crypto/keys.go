package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// RealityKeyPair holds generated X25519 keys formatted for Sing-box / Xray Reality
type RealityKeyPair struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	ShortID    string `json:"short_id"`
	UUID       string `json:"uuid"`
}

// GenerateRealityKeys generates a new X25519 keypair, random short ID, and user UUID
func GenerateRealityKeys() (*RealityKeyPair, error) {
	// 1. Generate X25519 keypair using standard library crypto/ecdh (Go 1.20+)
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate X25519 key: %w", err)
	}

	privBytes := priv.Bytes()
	pubBytes := priv.PublicKey().Bytes()

	// Sing-box & Xray use Base64 RawURLEncoding (no padding)
	privKeyBase64 := base64.RawURLEncoding.EncodeToString(privBytes)
	pubKeyBase64 := base64.RawURLEncoding.EncodeToString(pubBytes)

	// 2. Generate random 8-byte Short ID (16 hex chars)
	shortBytes := make([]byte, 8)
	if _, err := rand.Read(shortBytes); err != nil {
		return nil, fmt.Errorf("failed to generate short ID: %w", err)
	}
	shortID := hex.EncodeToString(shortBytes)

	// 3. Generate RFC 4122 v4 UUID
	uuidStr, err := GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate UUID: %w", err)
	}

	return &RealityKeyPair{
		PrivateKey: privKeyBase64,
		PublicKey:  pubKeyBase64,
		ShortID:    shortID,
		UUID:       uuidStr,
	}, nil
}

// GenerateUUID generates an RFC 4122 version 4 UUID
func GenerateUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// Set version 4
	b[6] = (b[6] & 0x0f) | 0x40
	// Set variant RFC 4122
	b[8] = (b[8] & 0x3f) | 0x80

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4],
		b[4:6],
		b[6:8],
		b[8:10],
		b[10:16],
	), nil
}
