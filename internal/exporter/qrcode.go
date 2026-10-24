package exporter

import (
	"fmt"

	"github.com/skip2/go-qrcode"
)

// PrintTerminalQR renders a compact ANSI QR-code directly in the terminal
func PrintTerminalQR(content string) error {
	qr, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		return fmt.Errorf("failed to generate QR code: %w", err)
	}

	// ToSmallString renders using unicode half-block characters (▄ / █ / ▀)
	asciiString := qr.ToSmallString(false)
	fmt.Println(asciiString)
	return nil
}
