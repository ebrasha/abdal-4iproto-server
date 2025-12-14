/*
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal 4iProto Server
 * File Name    : dnstt_gateway.go
 * Author       : Ebrahim Shafiei (EbraSha)
 * Email        : Prof.Shafiei@Gmail.com
 * Created On   : 2025-01-27 12:00:00
 * Description  : DNSTT (DNS Tunnel Toolkit) gateway implementation for tunneling TCP connections over DNS protocol
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

package main

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"log"
	mathrand "math/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// init seeds the math/rand package for random port selection
func init() {
	mathrand.Seed(time.Now().UnixNano())
}

// DNSTTSession represents an active DNSTT session
type DNSTTSession struct {
	ID           string
	RemoteAddr   string
	CreatedAt    time.Time
	LastActivity time.Time
	tcpConn      net.Conn
	readBuffer   []byte
	writeBuffer  []byte
	mu           sync.Mutex
}

// DNSTTGateway handles DNSTT connections using DNS protocol
type DNSTTGateway struct {
	listenAddr   string
	resolver     string
	nameserver   string
	publicKey    string
	serverPorts  []int
	sessions     map[string]*DNSTTSession
	sessionsMu   sync.RWMutex
	dnsServer    *dns.Server
	stopChan     chan struct{}
	wg           sync.WaitGroup
}

// NewDNSTTGateway creates a new DNSTT gateway instance
func NewDNSTTGateway(config ServerConfig) *DNSTTGateway {
	return &DNSTTGateway{
		listenAddr:  config.DNSTTListen,
		resolver:    config.DNSTTResolver,
		nameserver:  config.DNSTTNameserver,
		publicKey:   config.DNSTTPublicKey,
		serverPorts: config.Ports,
		sessions:    make(map[string]*DNSTTSession),
		stopChan:    make(chan struct{}),
	}
}

// generateDNSTTSessionID generates a unique session ID for DNSTT
func generateDNSTTSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// getRandomServerPort returns a random port from the server ports list
func (gw *DNSTTGateway) getRandomServerPort() int {
	if len(gw.serverPorts) == 0 {
		return 0
	}
	return gw.serverPorts[mathrand.Intn(len(gw.serverPorts))]
}

// decodeDNSTTData decodes data from DNS query name (subdomain)
func decodeDNSTTData(queryName string) ([]byte, error) {
	// Extract subdomain part (before the main domain)
	parts := strings.Split(queryName, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid query name format")
	}

	// Get the first part which contains encoded data
	encodedData := parts[0]
	
	// Remove common prefixes like "dnstt-" or "t-"
	encodedData = strings.TrimPrefix(encodedData, "dnstt-")
	encodedData = strings.TrimPrefix(encodedData, "t-")

	// Decode from base32 (DNSTT uses base32 encoding)
	decoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	data, err := decoder.DecodeString(strings.ToUpper(encodedData))
	if err != nil {
		// Try base64 as fallback
		data, err = base64.URLEncoding.DecodeString(encodedData)
		if err != nil {
			return nil, fmt.Errorf("failed to decode data: %w", err)
		}
	}

	return data, nil
}

// encodeDNSTTData encodes data for DNS response
func encodeDNSTTData(data []byte) string {
	// Encode to base32 (DNSTT uses base32 encoding)
	encoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	encoded := encoder.EncodeToString(data)
	return strings.ToLower(encoded)
}

// handleDNSTTQuery handles incoming DNS queries for DNSTT
func (gw *DNSTTGateway) handleDNSTTQuery(w dns.ResponseWriter, r *dns.Msg) {
	remoteAddr := w.RemoteAddr().String()
	userIP, _, _ := net.SplitHostPort(remoteAddr)

	// Extract query name
	if len(r.Question) == 0 {
		return
	}

	queryName := r.Question[0].Name
	queryType := r.Question[0].Qtype

	// Check if this is a DNSTT query (contains our nameserver domain)
	if !strings.Contains(queryName, gw.nameserver) {
		// Not a DNSTT query, ignore or handle as normal DNS
		return
	}

	// Try to decode data from query name
	data, err := decodeDNSTTData(queryName)
	if err != nil {
		// If decoding fails, this might be a new session initiation
		// Create a new session
		sessionID := generateDNSTTSessionID()
		
		// Get random server port for load balancing
		serverPort := gw.getRandomServerPort()
		if serverPort == 0 {
			log.Printf("❌ No server ports available for DNSTT connection from %s", remoteAddr)
			return
		}

		// Connect to 4iProto server port
		serverAddr := fmt.Sprintf("127.0.0.1:%d", serverPort)
		tcpConn, err := net.Dial("tcp", serverAddr)
		if err != nil {
			log.Printf("❌ Failed to connect to 4iProto server on port %d: %v", serverPort, err)
			return
		}

		// Optimize TCP connection settings
		if tcpConn, ok := tcpConn.(*net.TCPConn); ok {
			tcpConn.SetNoDelay(true)
			tcpConn.SetKeepAlive(true)
			tcpConn.SetKeepAlivePeriod(30 * time.Second)
		}

		// Create session
		session := &DNSTTSession{
			ID:           sessionID,
			RemoteAddr:   remoteAddr,
			CreatedAt:    time.Now(),
			LastActivity: time.Now(),
			tcpConn:      tcpConn,
			readBuffer:   make([]byte, 0),
			writeBuffer:  make([]byte, 0),
		}

		// Store session
		gw.sessionsMu.Lock()
		gw.sessions[sessionID] = session
		gw.sessionsMu.Unlock()

		// Log DNSTT connection
		logDNSTTConnection(userIP, sessionID, serverPort)

		// Start bidirectional data transfer
		go gw.handleDNSTTSession(session)

		// Send response with session ID
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true

		// Encode session ID in response
		sessionIDEncoded := encodeDNSTTData([]byte(sessionID))
		
		if queryType == dns.TypeTXT {
			txt := &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   queryName,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				Txt: []string{sessionIDEncoded},
			}
			m.Answer = append(m.Answer, txt)
		} else {
			// Default to A record with encoded data
			a := &dns.A{
				Hdr: dns.RR_Header{
					Name:   queryName,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: net.ParseIP("127.0.0.1"), // Placeholder IP
			}
			m.Answer = append(m.Answer, a)
		}

		w.WriteMsg(m)
		return
	}

	// This is data for an existing session
	// Find session by checking data header
	if len(data) < 8 {
		return
	}

	// Extract session ID from data (first 16 bytes)
	sessionIDBytes := data[:16]
	sessionID := string(sessionIDBytes)

	// Find session
	gw.sessionsMu.RLock()
	session, exists := gw.sessions[sessionID]
	gw.sessionsMu.RUnlock()

	if !exists {
		// Session not found, create new one
		return
	}

	// Update last activity
	session.mu.Lock()
	session.LastActivity = time.Now()
	session.mu.Unlock()

	// Write data to TCP connection (skip session ID header)
	if len(data) > 16 {
		payload := data[16:]
		if len(payload) > 0 {
			session.mu.Lock()
			if session.tcpConn != nil {
				_, err := session.tcpConn.Write(payload)
				if err != nil {
					log.Printf("⚠️ Failed to write to TCP connection for session %s: %v", sessionID[:16]+"...", err)
				}
			}
			session.mu.Unlock()
		}
	}

	// Read data from TCP connection for response
	session.mu.Lock()
	if session.tcpConn != nil {
		// Set read deadline
		session.tcpConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		
		buf := make([]byte, 512) // DNS response size limit
		n, err := session.tcpConn.Read(buf)
		if err == nil && n > 0 {
			// Store read data for next response
			session.readBuffer = append(session.readBuffer, buf[:n]...)
		}
	}
	session.mu.Unlock()

	// Prepare response
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	// Encode response data
	var responseData []byte
	session.mu.Lock()
	if len(session.readBuffer) > 0 {
		// Take up to 200 bytes for response (DNS limit)
		takeSize := 200
		if len(session.readBuffer) < takeSize {
			takeSize = len(session.readBuffer)
		}
		responseData = session.readBuffer[:takeSize]
		session.readBuffer = session.readBuffer[takeSize:]
	}
	session.mu.Unlock()

	if len(responseData) > 0 {
		encodedResponse := encodeDNSTTData(responseData)
		
		if queryType == dns.TypeTXT {
			txt := &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   queryName,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				Txt: []string{encodedResponse},
			}
			m.Answer = append(m.Answer, txt)
		} else {
			// Default to A record
			a := &dns.A{
				Hdr: dns.RR_Header{
					Name:   queryName,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: net.ParseIP("127.0.0.1"),
			}
			m.Answer = append(m.Answer, a)
		}
	} else {
		// No data to send, send empty response
		a := &dns.A{
			Hdr: dns.RR_Header{
				Name:   queryName,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    60,
			},
			A: net.ParseIP("127.0.0.1"),
		}
		m.Answer = append(m.Answer, a)
	}

	w.WriteMsg(m)
}

// handleDNSTTSession handles bidirectional data transfer for a DNSTT session
func (gw *DNSTTGateway) handleDNSTTSession(session *DNSTTSession) {
	defer func() {
		session.mu.Lock()
		if session.tcpConn != nil {
			session.tcpConn.Close()
		}
		session.mu.Unlock()

		// Remove session
		gw.sessionsMu.Lock()
		delete(gw.sessions, session.ID)
		gw.sessionsMu.Unlock()

		log.Printf("🔌 DNSTT session closed: %s from %s", session.ID[:16]+"...", session.RemoteAddr)
	}()

	log.Printf("🔗 New DNSTT session: %s from %s", session.ID[:16]+"...", session.RemoteAddr)

	// Keep session alive and handle cleanup
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-gw.stopChan:
			return
		case <-ticker.C:
			session.mu.Lock()
			lastActivity := session.LastActivity
			session.mu.Unlock()

			// Check if session is inactive (timeout after 5 minutes)
			if time.Since(lastActivity) > 5*time.Minute {
				log.Printf("⏱️ DNSTT session %s timed out", session.ID[:16]+"...")
				return
			}
		}
	}
}

// Start starts the DNSTT gateway DNS server
func (gw *DNSTTGateway) Start() error {
	if gw.listenAddr == "" {
		return fmt.Errorf("DNSTT listen address not configured")
	}

	// Parse listen address
	addr := gw.listenAddr
	if !strings.Contains(addr, ":") {
		addr = ":" + addr
	}

	// Create DNS server handler
	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		gw.handleDNSTTQuery(w, r)
	})

	// Start UDP DNS server (DNSTT primarily uses UDP)
	udpServer := &dns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: dns.DefaultServeMux,
	}

	// Start TCP DNS server (for larger queries)
	tcpServer := &dns.Server{
		Addr:    addr,
		Net:     "tcp",
		Handler: dns.DefaultServeMux,
	}

	gw.wg.Add(2)

	// Start UDP server
	go func() {
		defer gw.wg.Done()
		log.Printf("🚀 DNSTT Gateway (UDP) listening on %s", addr)
		if err := udpServer.ListenAndServe(); err != nil {
			log.Printf("❌ DNSTT UDP server error: %v", err)
		}
	}()

	// Start TCP server
	go func() {
		defer gw.wg.Done()
		log.Printf("🚀 DNSTT Gateway (TCP) listening on %s", addr)
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Printf("❌ DNSTT TCP server error: %v", err)
		}
	}()

	// Store server reference
	gw.dnsServer = udpServer

	return nil
}

// Stop stops the DNSTT gateway
func (gw *DNSTTGateway) Stop() error {
	close(gw.stopChan)

	if gw.dnsServer != nil {
		if err := gw.dnsServer.Shutdown(); err != nil {
			return err
		}
	}

	// Close all active sessions
	gw.sessionsMu.Lock()
	for _, session := range gw.sessions {
		session.mu.Lock()
		if session.tcpConn != nil {
			session.tcpConn.Close()
		}
		session.mu.Unlock()
	}
	gw.sessionsMu.Unlock()

	// Wait for all goroutines to finish
	gw.wg.Wait()

	log.Printf("🛑 DNSTT Gateway stopped")
	return nil
}

// startDNSTTGateway starts the DNSTT gateway in a separate goroutine
func startDNSTTGateway(config ServerConfig) {
	if !config.DNSTTEnabled {
		log.Printf("ℹ️  DNSTT Gateway is disabled in configuration")
		return
	}

	if config.DNSTTListen == "" {
		log.Printf("⚠️  DNSTT Gateway enabled but listen address not configured")
		return
	}

	if len(config.Ports) == 0 {
		log.Printf("⚠️  DNSTT Gateway enabled but no server ports configured")
		return
	}

	gateway := NewDNSTTGateway(config)
	if err := gateway.Start(); err != nil {
		log.Printf("❌ Failed to start DNSTT Gateway: %v", err)
		return
	}

	log.Printf("✅ DNSTT Gateway started successfully on %s", config.DNSTTListen)
}

// logDNSTTConnection logs DNSTT connection attempts (general connection log)
// Note: Username is not available at this stage (before SSH handshake)
// The actual target (website) will be logged in handleDirectTCPIP() when SSH channel is opened
func logDNSTTConnection(userIP string, sessionID string, serverPort int) {
	// Get executable directory and use it for file paths
	exeDir, err := SetExecutableDir()
	if err != nil {
		log.Printf("❌ Failed to get executable directory: %v", err)
		return
	}

	// Create dnstt_log directory if it doesn't exist
	dnsttLogDir := filepath.Join(exeDir, "dnstt_log")
	if err := os.MkdirAll(dnsttLogDir, 0755); err != nil {
		log.Printf("❌ Failed to create dnstt_log directory: %v", err)
		return
	}

	// Create log entry
	logEntry := fmt.Sprintf(
		"[🔗 DNSTT Connection] [%s] IP: %s | Session: %s | Server Port: %d\n",
		time.Now().Format("2006-01-02 15:04:05"),
		userIP,
		sessionID[:16]+"...",
		serverPort,
	)

	// Write to DNSTT connection log file
	filename := "dnstt_connections.log"
	fullPath := filepath.Join(dnsttLogDir, filename)
	f, err := os.OpenFile(fullPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Failed to open DNSTT log file %s: %v", filename, err)
		return
	}
	defer f.Close()

	if _, err := f.WriteString(logEntry); err != nil {
		log.Printf("Failed to write DNSTT connection log: %v", err)
	}
}
