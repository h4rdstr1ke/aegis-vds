package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os/exec"
	"runtime"
	"strconv"
	"time"

	"aegis-vds/internal/crypto"
	"aegis-vds/internal/deployer"
	"aegis-vds/internal/exporter"
	"aegis-vds/internal/probe"
	"aegis-vds/internal/sshclient"
	"github.com/skip2/go-qrcode"
)

// Server handles UI HTTP requests and API endpoints
type Server struct {
	port            int
	frontendFS      fs.FS
	AutoOpenBrowser bool
}

// NewServer initializes the HTTP server with embedded frontend assets
func NewServer(port int, frontendFS fs.FS, autoOpenBrowser bool) *Server {
	return &Server{
		port:            port,
		frontendFS:      frontendFS,
		AutoOpenBrowser: autoOpenBrowser,
	}
}

// Start runs the HTTP server
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/sni/scan", s.handleSNIScan)
	mux.HandleFunc("/api/vds/probe", s.handleVDSProbe)
	mux.HandleFunc("/api/vds/deploy", s.handleVDSDeploy)
	mux.HandleFunc("/api/local/vpn", s.handleLocalVPN)

	// Static web files
	fileServer := http.FileServer(http.FS(s.frontendFS))
	mux.Handle("/", fileServer)

	addr := fmt.Sprintf("127.0.0.1:%d", s.port)

	if s.AutoOpenBrowser {
		fmt.Printf("\n  🚀 AegisVDS UI Server running at: http://%s\n", addr)
		go func() {
			time.Sleep(300 * time.Millisecond)
			OpenBrowser(fmt.Sprintf("http://%s", addr))
		}()
	}

	return http.ListenAndServe(addr, mux)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":  "running",
		"version": "1.0.0",
		"os":      runtime.GOOS,
		"arch":    runtime.GOARCH,
	})
}

func (s *Server) handleSNIScan(w http.ResponseWriter, r *http.Request) {
	best, allResults := probe.FindBestSNI(nil)

	type sniItem struct {
		Domain     string `json:"domain"`
		IsWorking  bool   `json:"is_working"`
		HasTLS13   bool   `json:"has_tls13"`
		SupportsH2 bool   `json:"supports_h2"`
		LatencyMs  int64  `json:"latency_ms"`
		Error      string `json:"error,omitempty"`
	}

	var items []sniItem
	for _, res := range allResults {
		items = append(items, sniItem{
			Domain:     res.Domain,
			IsWorking:  res.IsWorking,
			HasTLS13:   res.HasTLS13,
			SupportsH2: res.SupportsH2,
			LatencyMs:  res.Latency.Milliseconds(),
			Error:      res.Error,
		})
	}

	var bestDomain string
	if best != nil {
		bestDomain = best.Domain
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"best_domain": bestDomain,
		"candidates":  items,
	})
}

type VDSProbeRequest struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	KeyPath  string `json:"key_path"`
}

func (s *Server) handleVDSProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req VDSProbeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if req.Host == "" {
		jsonError(w, "Host is required", http.StatusBadRequest)
		return
	}
	if req.Port == 0 {
		req.Port = 22
	}
	if req.User == "" {
		req.User = "root"
	}

	client, err := sshclient.Dial(sshclient.Config{
		Host:     req.Host,
		Port:     req.Port,
		User:     req.User,
		Password: req.Password,
		KeyPath:  req.KeyPath,
		Timeout:  8 * time.Second,
	})
	if err != nil {
		jsonError(w, fmt.Sprintf("SSH connection failed: %v", err), http.StatusBadGateway)
		return
	}
	defer client.Close()

	// 1. Inspect System
	sysInfo, err := probe.InspectSystem(client)
	if err != nil {
		jsonError(w, fmt.Sprintf("Failed to inspect system: %v", err), http.StatusInternalServerError)
		return
	}

	// 2. Fetch Geo/IP Info
	ipInfo, _ := probe.FetchIPInfo(req.Host)

	// 3. Measure Latency
	latency := probe.MeasureLatency(req.Host, req.Port, 3)

	// 4. DPI & Protocol Evaluation
	dpiReport := probe.EvaluateProtocols(client, sysInfo, req.Host)

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"system":     sysInfo,
		"ip_info":    ipInfo,
		"latency":    latency,
		"dpi_report": dpiReport,
	})
}

type VDSDeployRequest struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	User       string `json:"user"`
	Password   string `json:"password"`
	KeyPath    string `json:"key_path"`
	TargetSNI  string `json:"target_sni"`
	VlessPort  int    `json:"vless_port"`
	EnableBBR  bool   `json:"enable_bbr"`
}

func (s *Server) handleVDSDeploy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req VDSDeployRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if req.Host == "" {
		jsonError(w, "Host is required", http.StatusBadRequest)
		return
	}
	if req.Port == 0 {
		req.Port = 22
	}
	if req.User == "" {
		req.User = "root"
	}
	if req.VlessPort == 0 {
		req.VlessPort = 443
	}
	if req.TargetSNI == "" {
		req.TargetSNI = "dl.google.com"
	}

	client, err := sshclient.Dial(sshclient.Config{
		Host:     req.Host,
		Port:     req.Port,
		User:     req.User,
		Password: req.Password,
		KeyPath:  req.KeyPath,
		Timeout:  10 * time.Second,
	})
	if err != nil {
		jsonError(w, fmt.Sprintf("SSH connection failed: %v", err), http.StatusBadGateway)
		return
	}
	defer client.Close()

	// 1. Enable BBR if requested
	if req.EnableBBR {
		_, _ = deployer.EnableBBR(client)
	}

	// 2. Generate keys
	keys, err := crypto.GenerateRealityKeys()
	if err != nil {
		jsonError(w, fmt.Sprintf("Key generation failed: %v", err), http.StatusInternalServerError)
		return
	}

	// 3. Deploy Sing-box
	err = deployer.DeploySingBox(client, deployer.DeployConfig{
		Port:      req.VlessPort,
		TargetSNI: req.TargetSNI,
		Keys:      keys,
	})
	if err != nil {
		jsonError(w, fmt.Sprintf("Deployment failed: %v", err), http.StatusInternalServerError)
		return
	}

	// 4. Generate client configuration & VLESS link
	exportParams := exporter.ExportParams{
		Host:      req.Host,
		Port:      req.VlessPort,
		TargetSNI: req.TargetSNI,
		Keys:      keys,
		Remark:    fmt.Sprintf("AegisVDS-%s", req.Host),
	}

	vlessLink := exporter.GenerateVLESSLink(exportParams)

	// Generate QR code PNG in base64
	pngBytes, err := qrcode.Encode(vlessLink, qrcode.Medium, 320)
	var qrBase64 string
	if err == nil {
		qrBase64 = "data:image/png;base64," + base64.StdEncoding.EncodeToString(pngBytes)
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success":    true,
		"vless_link": vlessLink,
		"qr_code":    qrBase64,
		"keys": map[string]string{
			"uuid":       keys.UUID,
			"public_key": keys.PublicKey,
			"short_id":   keys.ShortID,
		},
		"sni":  req.TargetSNI,
		"port": req.VlessPort,
	})
}

func jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, message string, status int) {
	jsonResponse(w, status, map[string]interface{}{
		"error": message,
	})
}

// OpenBrowser opens the specified URL in the default browser of the system
func OpenBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	}
	if cmd != nil {
		_ = cmd.Start()
	}
}

// ParsePortOrDefault parses port string
func ParsePortOrDefault(val string, defaultVal int) int {
	p, err := strconv.Atoi(val)
	if err != nil || p <= 0 {
		return defaultVal
	}
	return p
}

func (s *Server) handleLocalVPN(w http.ResponseWriter, r *http.Request) {
	vpnStatus, err := probe.InspectLocalVPN()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonResponse(w, http.StatusOK, vpnStatus)
}
