package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"aegis-vds/internal/crypto"
	"aegis-vds/internal/deployer"
	"aegis-vds/internal/exporter"
	"aegis-vds/internal/probe"
	"aegis-vds/internal/sshclient"
	"aegis-vds/internal/ui"
)

func main() {
	ui.PrintBanner()

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "probe":
			runProbeCommand(os.Args[2:])
			return
		case "scan-sni":
			runScanSNICommand(os.Args[2:])
			return
		case "help", "--help", "-h":
			printUsage()
			return
		}
	}

	// Default to interactive wizard
	runWizard()
}

func printUsage() {
	fmt.Printf("%sUsage:%s\n", ui.Bold, ui.Reset)
	fmt.Println("  aegis                 Launch interactive wizard (Diagnostics & Deploy)")
	fmt.Println("  aegis probe [flags]   Perform full VDS and DPI diagnostics without deploying")
	fmt.Println("  aegis scan-sni        Scan and rank candidate SNI masking domains for Reality")
	fmt.Println("  aegis help            Show this help message")
	fmt.Println()
	fmt.Printf("%sFlags for probe:%s\n", ui.Bold, ui.Reset)
	fmt.Println("  -h, --host    VDS IP or hostname")
	fmt.Println("  -p, --port    SSH port (default: 22)")
	fmt.Println("  -u, --user    SSH username (default: root)")
	fmt.Println("  -k, --key     Path to SSH private key")
}

func runWizard() {
	ui.Header("Interactive VDS Censorship Audit & Deployment")

	host := ui.Prompt("Enter VDS IP address / Hostname", "")
	if host == "" {
		ui.Error("Host is required to continue")
		os.Exit(1)
	}

	portStr := ui.Prompt("SSH Port", "22")
	port, _ := strconv.Atoi(portStr)
	if port <= 0 {
		port = 22
	}

	user := ui.Prompt("SSH Username", "root")

	authChoice := ui.Prompt("Authentication [1: Password, 2: SSH Key]", "1")
	var password, keyPath string

	if authChoice == "2" {
		keyPath = ui.Prompt("Path to SSH private key", "~/.ssh/id_ed25519")
	} else {
		var err error
		password, err = ui.PromptPassword("SSH Password")
		if err != nil {
			ui.Error("Failed to read password: %v", err)
			os.Exit(1)
		}
	}

	sshCfg := sshclient.Config{
		Host:     host,
		Port:     port,
		User:     user,
		Password: password,
		KeyPath:  keyPath,
	}

	// 1. Connect
	ui.Step(1, 5, "Connecting to VDS via SSH")
	client, err := sshclient.Dial(sshCfg)
	if err != nil {
		ui.Error("Connection failed: %v", err)
		os.Exit(1)
	}
	defer client.Close()
	ui.Success("Connected to %s@%s:%d successfully", user, host, port)

	// 2. System Inspection
	ui.Step(2, 5, "Inspecting VDS hardware and capabilities")
	sysInfo, err := probe.InspectSystem(client)
	if err != nil {
		ui.Warn("Could not fetch full system info: %v", err)
	} else {
		ui.PrintRow("OS Distribution", sysInfo.OS)
		ui.PrintRow("Kernel", sysInfo.Kernel)
		ui.PrintRow("Architecture", sysInfo.Architecture)
		ui.PrintRow("Virtualization", sysInfo.Virtualization)
		ui.PrintRow("Memory (RAM)", sysInfo.RAMTotalMB)
		ui.PrintRow("Disk Space", sysInfo.DiskFree)
		ui.PrintRow("TUN / TAP Device", boolBadge(sysInfo.HasTUN))
		ui.PrintRow("TCP BBR Status", sysInfo.BBRStatus)
	}

	// 3. Network & DPI Probe
	ui.Step(3, 5, "Network & Censorship Probe (Client <-> VDS)")
	ipInfo, err := probe.FetchIPInfo(host)
	if err == nil {
		ui.PrintRow("Location", fmt.Sprintf("%s, %s", ipInfo.City, ipInfo.Country))
		ui.PrintRow("ISP / Org", fmt.Sprintf("%s (%s)", ipInfo.ISP, ipInfo.AS))
	}

	latency := probe.MeasureLatency(host, port, 4)
	ui.PrintRow("Latency (RTT)", fmt.Sprintf("Avg: %v (Min: %v, Max: %v)", latency.AvgRTT.Round(100*1e3), latency.MinRTT.Round(100*1e3), latency.MaxRTT.Round(100*1e3)))
	ui.PrintRow("Jitter", fmt.Sprintf("%v", latency.Jitter.Round(100*1e3)))
	ui.PrintRow("Packet Loss", fmt.Sprintf("%.0f%%", latency.LossRate))

	dpiReport := probe.EvaluateProtocols(client, sysInfo, host)
	ui.PrintRow("UDP Filtering", dpiReport.UDPFilterStatus)

	// 4. Reality SNI Target Discovery
	ui.Step(4, 5, "Scanning optimal Reality SNI disguise domains")
	bestSNI, allSNIs := probe.FindBestSNI(nil)

	for _, sni := range allSNIs {
		status := fmt.Sprintf("%sFAIL%s", ui.Red, ui.Reset)
		if sni.IsWorking && sni.HasTLS13 {
			status = fmt.Sprintf("%sTLS 1.3 OK%s (%v)", ui.Green, ui.Reset, sni.Latency.Round(100*1e3))
		}
		ui.PrintRow(sni.Domain, status)
	}

	chosenSNI := "dl.google.com"
	if bestSNI != nil {
		chosenSNI = bestSNI.Domain
		ui.Success("Selected top SNI mask: %s%s%s (TLS 1.3 + H2, RTT: %v)", ui.Bold, chosenSNI, ui.Reset, bestSNI.Latency.Round(100*1e3))
	} else {
		ui.Warn("Defaulting to fallback SNI: %s", chosenSNI)
	}

	// Display Protocol Compatibility Matrix
	ui.Header("Protocol Compatibility Assessment")
	for _, rec := range dpiReport.Recommendations {
		gradeColor := ui.Green
		if rec.Grade == probe.GradeRisky {
			gradeColor = ui.Yellow
		} else if rec.Grade == probe.GradeBlocked {
			gradeColor = ui.Red
		}
		fmt.Printf("  [%s%s%s] %s%-28s%s -> %s\n", gradeColor, rec.Grade, ui.Reset, ui.Bold, rec.Name, ui.Reset, rec.Status)
		fmt.Printf("        %s%s%s\n", ui.Dim, rec.Description, ui.Reset)
	}

	// Confirmation
	fmt.Println()
	confirm := ui.Prompt(fmt.Sprintf("Proceed with automatic deployment of %sVLESS + Reality%s on port 443? [Y/n]", ui.Bold, ui.Reset), "Y")
	if strings.ToLower(confirm) != "y" && confirm != "" {
		ui.Info("Deployment cancelled by user. Exiting.")
		return
	}

	// 5. Deploy Sing-box & Keys
	ui.Step(5, 5, "Generating keys & deploying Sing-box to VDS")

	// Enable BBR
	bbrEnabled, _ := deployer.EnableBBR(client)
	if bbrEnabled {
		ui.Success("TCP BBR congestion control activated on VDS")
	}

	// Keys
	keys, err := crypto.GenerateRealityKeys()
	if err != nil {
		ui.Error("Failed to generate Reality cryptographic keys: %v", err)
		os.Exit(1)
	}
	ui.Success("Generated X25519 keypair and short ID")

	// Deploy
	err = deployer.DeploySingBox(client, deployer.DeployConfig{
		Port:      443,
		TargetSNI: chosenSNI,
		Keys:      keys,
	})
	if err != nil {
		ui.Error("Deployment failed: %v", err)
		os.Exit(1)
	}
	ui.Success("Sing-box service successfully deployed and running on port 443!")

	// 6. Output Configs & QR Code
	exportParams := exporter.ExportParams{
		Host:      host,
		Port:      443,
		TargetSNI: chosenSNI,
		Keys:      keys,
		Remark:    fmt.Sprintf("AegisVDS-%s", host),
	}

	vlessLink := exporter.GenerateVLESSLink(exportParams)
	clientConfigPath := "aegis-client-config.json"
	exporter.GenerateClientJSON(exportParams, clientConfigPath)

	ui.Header("DEPLOYMENT COMPLETE — ACCESS CONFIGURATION")
	fmt.Printf("\n%sVLESS Reality Link (Copy & Import into Hiddify, Sing-box, v2rayN, Streisand):%s\n\n", ui.Bold, ui.Reset)
	fmt.Printf("%s%s%s\n\n", ui.Cyan, vlessLink, ui.Reset)

	fmt.Printf("%sScan QR Code with mobile camera or VPN app:%s\n\n", ui.Bold, ui.Reset)
	exporter.PrintTerminalQR(vlessLink)

	ui.Success("Desktop client configuration saved to: %s", clientConfigPath)
	fmt.Println()
}

func runProbeCommand(args []string) {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	host := fs.String("h", "", "VDS host or IP")
	port := fs.Int("p", 22, "SSH port")
	user := fs.String("u", "root", "SSH user")
	keyPath := fs.String("k", "", "Path to private key")
	fs.Parse(args)

	if *host == "" {
		ui.Error("Flag -h (host) is required")
		os.Exit(1)
	}

	var password string
	if *keyPath == "" {
		var err error
		password, err = ui.PromptPassword("SSH Password (leave blank if using agent)")
		if err != nil {
			os.Exit(1)
		}
	}

	client, err := sshclient.Dial(sshclient.Config{
		Host:     *host,
		Port:     *port,
		User:     *user,
		Password: password,
		KeyPath:  *keyPath,
	})
	if err != nil {
		ui.Error("Failed to connect: %v", err)
		os.Exit(1)
	}
	defer client.Close()

	ui.Header("Running VDS Diagnostics")
	sysInfo, _ := probe.InspectSystem(client)
	if sysInfo != nil {
		ui.PrintRow("OS", sysInfo.OS)
		ui.PrintRow("Virtualization", sysInfo.Virtualization)
		ui.PrintRow("Memory", sysInfo.RAMTotalMB)
		ui.PrintRow("TUN Device", boolBadge(sysInfo.HasTUN))
		ui.PrintRow("BBR Status", sysInfo.BBRStatus)
	}

	report := probe.EvaluateProtocols(client, sysInfo, *host)
	ui.PrintRow("UDP Filtering", report.UDPFilterStatus)

	ui.Header("Protocol Compatibility")
	for _, rec := range report.Recommendations {
		fmt.Printf("  [%s] %-28s -> %s\n", rec.Grade, rec.Name, rec.Status)
	}
}

func runScanSNICommand(args []string) {
	ui.Header("Reality SNI Disguise Domain Scanner")
	best, results := probe.FindBestSNI(nil)

	for _, sni := range results {
		status := fmt.Sprintf("%sFAIL%s", ui.Red, ui.Reset)
		if sni.IsWorking && sni.HasTLS13 {
			status = fmt.Sprintf("%sTLS 1.3 + H2 OK%s (%v)", ui.Green, ui.Reset, sni.Latency.Round(100*1e3))
		}
		ui.PrintRow(sni.Domain, status)
	}

	if best != nil {
		ui.Success("\nOptimal Domain: %s%s%s (RTT: %v)", ui.Bold, best.Domain, ui.Reset, best.Latency.Round(100*1e3))
	}
}

func boolBadge(b bool) string {
	if b {
		return fmt.Sprintf("%sAvailable%s", ui.Green, ui.Reset)
	}
	return fmt.Sprintf("%sNot available%s", ui.Red, ui.Reset)
}
