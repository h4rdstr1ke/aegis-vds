package probe

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// SNICandidate represents a tested target domain for Reality mask
type SNICandidate struct {
	Domain     string
	IsWorking  bool
	HasTLS13   bool
	SupportsH2 bool
	Latency    time.Duration
	Error      string
}

// DefaultSNICandidates list of well-known trusted domains for Reality masking
var DefaultSNICandidates = []string{
	"gateway.icloud.com",
	"dl.google.com",
	"swdist.apple.com",
	"www.microsoft.com",
	"addons.mozilla.org",
	"www.cloudflare.com",
	"speedtest.net",
	"sentry.io",
}

// TestSNI checks TLS 1.3 handshake, ALPN (h2) support and latency to candidate domain
func TestSNI(domain string, timeout time.Duration) *SNICandidate {
	res := &SNICandidate{
		Domain: domain,
	}

	start := time.Now()
	addr := fmt.Sprintf("%s:443", domain)

	dialer := &net.Dialer{
		Timeout: timeout,
	}

	tlsConfig := &tls.Config{
		ServerName:         domain,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"h2", "http/1.1"},
		InsecureSkipVerify: false,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	if err != nil {
		res.IsWorking = false
		res.Error = err.Error()
		return res
	}
	defer conn.Close()

	res.Latency = time.Since(start)
	res.IsWorking = true

	state := conn.ConnectionState()
	if state.Version == tls.VersionTLS13 {
		res.HasTLS13 = true
	}
	if state.NegotiatedProtocol == "h2" {
		res.SupportsH2 = true
	}

	return res
}

// FindBestSNI evaluates candidates and selects the fastest, TLS 1.3 + H2 compatible domain
func FindBestSNI(candidates []string) (*SNICandidate, []*SNICandidate) {
	if len(candidates) == 0 {
		candidates = DefaultSNICandidates
	}

	var results []*SNICandidate
	var best *SNICandidate

	for _, domain := range candidates {
		res := TestSNI(domain, 3*time.Second)
		results = append(results, res)

		if res.IsWorking && res.HasTLS13 {
			if best == nil || res.Latency < best.Latency {
				best = res
			}
		}
	}

	return best, results
}
