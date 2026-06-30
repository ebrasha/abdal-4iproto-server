/*
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal 4iProto Server
 * File Name    : config.go
 * Programmer   : Ebrahim Shafiei (EbraSha)
 * Email        : Prof.Shafiei@Gmail.com
 * Created On   : 2026-06-30 04:12:29
 * Description  : SSH server configuration and host key setup
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

package sshserver

import (
	"fmt"
	"log"
	"net"
	"os"
	"sync"

	"Abdal_4iProto_Server/core/config"
	"Abdal_4iProto_Server/core/logging"
	"Abdal_4iProto_Server/core/security"
	"Abdal_4iProto_Server/core/session"
	"Abdal_4iProto_Server/core/traffic"

	"golang.org/x/crypto/ssh"
)

// Handler coordinates SSH connection handling with injected dependencies.
type Handler struct {
	Sessions *session.Manager
	Traffic  *traffic.Store
	Guard    *security.Guard
}

var sessionMetadata sync.Map

// BuildServerConfig creates the shared SSH server configuration used by all listeners.
func (h *Handler) BuildServerConfig() *ssh.ServerConfig {
	cfg := config.Server()
	serverCfg := &ssh.ServerConfig{
		ServerVersion: cfg.ServerVersion,
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			return h.passwordCallback(c, pass)
		},
	}

	serverCfg.Config = ssh.Config{
		Ciphers: []string{
			"chacha20-poly1305@openssh.com",
			"aes128-gcm@openssh.com",
			"aes256-ctr",
			"aes192-ctr",
			"aes128-ctr",
		},
		KeyExchanges: []string{
			"curve25519-sha256",
			"diffie-hellman-group14-sha1",
		},
		MACs: []string{
			"hmac-sha2-256-etm@openssh.com",
			"hmac-sha2-256",
			"hmac-sha1",
		},
	}

	privateKeyPath, err := config.PrivateKeyPath()
	if err != nil {
		log.Fatalf("Failed to get private key path: %v", err)
	}

	privateBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		log.Fatalf("Failed to load private key from %s: %s", privateKeyPath, err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatalf("Failed to parse private key: %s", err)
	}

	serverCfg.AddHostKey(private)
	return serverCfg
}

func (h *Handler) passwordCallback(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
	ip, portStr, _ := net.SplitHostPort(c.RemoteAddr().String())
	clientPort := 0
	if portStr != "" {
		fmt.Sscanf(portStr, "%d", &clientPort)
	}

	_, serverPortStr, _ := net.SplitHostPort(c.LocalAddr().String())
	serverPort := 0
	if serverPortStr != "" {
		fmt.Sscanf(serverPortStr, "%d", &serverPort)
	}

	if h.Guard.IsBlocked(ip) {
		log.Printf("⛔ Blocked IP tried to connect: %s", ip)
		return nil, fmt.Errorf("your IP is blocked")
	}

	user, ok := config.GetUser(c.User())
	if !ok || user.Password != string(pass) {
		logging.InvalidLogin(c.User(), string(pass), ip, clientPort, serverPort)
		attempts, shouldBlock := h.Guard.RecordFailedLogin(ip)
		log.Printf("❌ Failed login from %s (%d attempts)", ip, attempts)
		if shouldBlock {
			if h.Guard.AddBlockedIP(ip) {
				log.Printf("🚫 Blocking IP: %s", ip)
			}
		}
		return nil, fmt.Errorf("authentication failed")
	}

	h.Guard.ClearFailedAttempts(ip)

	if err := h.Traffic.CheckUserTrafficLimit(c.User(), user.MaxTotalMB); err != nil {
		log.Printf("🚫 User %s from %s rejected: traffic limit exceeded", c.User(), ip)
		return nil, err
	}

	clientVersion := "SSH-2.0-Unknown"
	sessionID, err := h.Sessions.CreateSession(c.User(), ip, clientVersion)
	if err != nil {
		log.Printf("🚫 Failed to create session for %s from %s: %v", c.User(), ip, err)
		return nil, err
	}

	sessionMetadata.Store(c.User()+"|"+ip, sessionID)
	log.Printf("✅ User %s (%s) authenticated from %s [Session: %s]", c.User(), user.Role, ip, sessionID[:16]+"...")

	return &ssh.Permissions{
		Extensions: map[string]string{
			"session_id": sessionID,
		},
	}, nil
}
