package probe

import (
	"testing"
)

func TestInspectLocalVPN(t *testing.T) {
	status, err := InspectLocalVPN()
	if err != nil {
		t.Fatalf("InspectLocalVPN returned error: %v", err)
	}

	if status == nil {
		t.Fatal("Expected non-nil LocalVPNStatus")
	}

	// In test environment, status should at least have measured latency or interface list
	t.Logf("VPN Detected: %v, Protocol: %s, Iface: %s, IP: %s, Latency: %d ms",
		status.IsConnected, status.Protocol, status.InterfaceName, status.PublicIP, status.LatencyMs)
}
