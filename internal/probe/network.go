package probe

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"time"
)

// IPInfo holds public geo-location and ASN metadata
type IPInfo struct {
	Query       string `json:"query"`
	Country     string `json:"country"`
	CountryCode string `json:"countryCode"`
	City        string `json:"city"`
	ISP         string `json:"isp"`
	Org         string `json:"org"`
	AS          string `json:"as"`
}

// LatencyStats holds ping metrics between client and VDS
type LatencyStats struct {
	MinRTT    time.Duration
	AvgRTT    time.Duration
	MaxRTT    time.Duration
	Jitter    time.Duration
	LossRate  float64
	OpenPorts []int
}

// FetchIPInfo retrieves public network metadata for the given host
func FetchIPInfo(host string) (*IPInfo, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,countryCode,city,isp,org,as,query", host)

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to query IP info: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Status string `json:"status"`
		IPInfo
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result.IPInfo, nil
}

// MeasureLatency measures TCP ping and jitter to the server
func MeasureLatency(host string, port int, count int) *LatencyStats {
	if count <= 0 {
		count = 5
	}
	var rtts []time.Duration
	var failures int

	addr := fmt.Sprintf("%s:%d", host, port)

	for i := 0; i < count; i++ {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			failures++
		} else {
			rtt := time.Since(start)
			rtts = append(rtts, rtt)
			conn.Close()
		}
		time.Sleep(100 * time.Millisecond)
	}

	stats := &LatencyStats{
		LossRate: float64(failures) / float64(count) * 100,
	}

	if len(rtts) > 0 {
		var sum time.Duration
		stats.MinRTT = rtts[0]
		stats.MaxRTT = rtts[0]

		for _, rtt := range rtts {
			sum += rtt
			if rtt < stats.MinRTT {
				stats.MinRTT = rtt
			}
			if rtt > stats.MaxRTT {
				stats.MaxRTT = rtt
			}
		}
		stats.AvgRTT = sum / time.Duration(len(rtts))

		// Calculate jitter (mean absolute deviation)
		var jitterSum float64
		for _, rtt := range rtts {
			jitterSum += math.Abs(float64(rtt - stats.AvgRTT))
		}
		stats.Jitter = time.Duration(jitterSum / float64(len(rtts)))
	}

	return stats
}
