package sshclient

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Config contains SSH connection details
type Config struct {
	Host     string
	Port     int
	User     string
	Password string
	KeyPath  string
	Timeout  time.Duration
}

// Client wraps an active SSH client connection
type Client struct {
	rawClient *ssh.Client
	config    Config
}

// Dial connects to the remote VDS via SSH
func Dial(cfg Config) (*Client, error) {
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	if cfg.User == "" {
		cfg.User = "root"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}

	var authMethods []ssh.AuthMethod

	// 1. Private key if provided
	if cfg.KeyPath != "" {
		expandedPath := expandHome(cfg.KeyPath)
		keyBytes, err := os.ReadFile(expandedPath)
		if err == nil {
			signer, err := ssh.ParsePrivateKey(keyBytes)
			if err == nil {
				authMethods = append(authMethods, ssh.PublicKeys(signer))
			}
		}
	} else {
		// Check default key locations (~/.ssh/id_ed25519, ~/.ssh/id_rsa)
		for _, defaultKey := range []string{"~/.ssh/id_ed25519", "~/.ssh/id_rsa"} {
			expanded := expandHome(defaultKey)
			if keyBytes, err := os.ReadFile(expanded); err == nil {
				if signer, err := ssh.ParsePrivateKey(keyBytes); err == nil {
					authMethods = append(authMethods, ssh.PublicKeys(signer))
					break
				}
			}
		}
	}

	// 2. Password auth if provided
	if cfg.Password != "" {
		authMethods = append(authMethods, ssh.Password(cfg.Password))
	}

	if len(authMethods) == 0 {
		return nil, fmt.Errorf("no SSH authentication method available (provide password or SSH key)")
	}

	clientConfig := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // For new/reinstalled VDS nodes
		Timeout:         cfg.Timeout,
	}

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	client, err := ssh.Dial("tcp", addr, clientConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to dial SSH %s: %w", addr, err)
	}

	return &Client{
		rawClient: client,
		config:    cfg,
	}, nil
}

// Close closes the SSH connection
func (c *Client) Close() error {
	if c.rawClient != nil {
		return c.rawClient.Close()
	}
	return nil
}

// Run executes a remote command and returns its combined stdout/stderr
func (c *Client) Run(cmd string) (string, error) {
	session, err := c.rawClient.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer session.Close()

	var buf bytes.Buffer
	session.Stdout = &buf
	session.Stderr = &buf

	err = session.Run(cmd)
	output := strings.TrimSpace(buf.String())
	if err != nil {
		return output, fmt.Errorf("command '%s' failed: %w (output: %s)", cmd, err, output)
	}
	return output, nil
}

// WriteFile writes data to a remote file on the server using cat / sudo
func (c *Client) WriteFile(remotePath string, content []byte, perm string) error {
	session, err := c.rawClient.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer session.Close()

	session.Stdin = bytes.NewReader(content)
	dir := filepath.Dir(remotePath)
	cmd := fmt.Sprintf("mkdir -p %s && cat > %s && chmod %s %s", dir, remotePath, perm, remotePath)
	if out, err := session.CombinedOutput(cmd); err != nil {
		return fmt.Errorf("failed to write %s: %w (%s)", remotePath, err, string(out))
	}
	return nil
}

func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}
