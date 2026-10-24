package ui

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// ANSI color codes
const (
	Reset   = "\033[0m"
	Bold    = "\033[1m"
	Dim     = "\033[2m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	White   = "\033[37m"
	BgBlue  = "\033[44m"
)

// PrintBanner prints the AegisVDS ASCII logo and subtitle
func PrintBanner() {
	banner := `
   ___    ______ _____ _____ _____   _    ______  _____ 
  /   |  / ____// ___// ___// ___/  | |  / / __ \/ ___/ 
 / /| | / __/  / (_ // /\__ \\__ \  | | / / / / /\__ \  
/ ___ |/ /___  \___// /___/ /__/ /  | |/ / /_/ /___/ /  
/_/  |_/_____/ /____//____//____/    |___/_____//____/   
`
	fmt.Printf("%s%s%s%s\n", Cyan, Bold, banner, Reset)
	fmt.Printf("   %s%s[AEGIS] Next-Gen VDS Censorship Diagnostics & Zero-Touch Deployer%s\n", White, Bold, Reset)
	fmt.Printf("   %sAutomatic DPI testing, Reality SNI scanner & Sing-box provisioner%s\n\n", Dim, Reset)
}

func Header(text string) {
	fmt.Printf("\n%s%s==> %s%s\n", Cyan, Bold, text, Reset)
}

func Step(step int, total int, text string) {
	fmt.Printf("\n%s[%d/%d]%s %s%s%s\n", Yellow, step, total, Reset, Bold, text, Reset)
}

func Success(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	fmt.Printf("  %s✓%s %s\n", Green, Reset, msg)
}

func Info(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	fmt.Printf("  %sℹ%s %s\n", Blue, Reset, msg)
}

func Warn(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	fmt.Printf("  %s!%s %s%s%s\n", Yellow, Reset, Yellow, msg, Reset)
}

func Error(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	fmt.Printf("  %s✗%s %s%s%s\n", Red, Reset, Red, msg, Reset)
}

func Prompt(label string, defaultValue string) string {
	reader := bufio.NewReader(os.Stdin)
	if defaultValue != "" {
		fmt.Printf("  %s%s%s [%s%s%s]: ", Bold, label, Reset, Cyan, defaultValue, Reset)
	} else {
		fmt.Printf("  %s%s%s: ", Bold, label, Reset)
	}

	input, err := reader.ReadString('\n')
	if err != nil {
		return defaultValue
	}
	input = strings.TrimSpace(input)
	if input == "" {
		return defaultValue
	}
	return input
}

func PromptPassword(label string) (string, error) {
	fmt.Printf("  %s%s%s: ", Bold, label, Reset)
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(bytePassword)), nil
}

func PrintRow(key string, val string) {
	fmt.Printf("  %-24s : %s%s%s\n", key, Bold, val, Reset)
}
