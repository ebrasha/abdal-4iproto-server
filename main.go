/*
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal 4iProto Server
 * File Name    : main.go
 * Author       : Ebrahim Shafiei (EbraSha)
 * Email        : Prof.Shafiei@Gmail.com
 * Created On   : 2025-09-10 22:12:41
 * Description  : High-performance SSH-based tunneling server with advanced security features, traffic monitoring, and brute force protection
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var trafficMap sync.Map // key: username, value: *TrafficStats
var activeConnections sync.Map // key: connection ID, value: connection info

// SetExecutableDir changes current working directory to exe dir and returns it.
func SetExecutableDir() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to get executable path: %w", err)
	}

	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve symlinks: %w", err)
	}

	exeDir := filepath.Dir(exePath)

	if err := os.Chdir(exeDir); err != nil {
		return "", fmt.Errorf("failed to change working directory: %w", err)
	}

	return exeDir, nil
}

// getTrafficMapSize returns the number of entries in trafficMap
func getTrafficMapSize() int {
	count := 0
	trafficMap.Range(func(key, value any) bool {
		count++
		return true
	})
	return count
}

// getActiveConnectionsCount returns the number of active connections
func getActiveConnectionsCount() int {
	count := 0
	activeConnections.Range(func(key, value any) bool {
		count++
		return true
	})
	return count
}

// Save per-user traffic data
type TrafficStats struct {
	Username           string `json:"username"`             // Username connected to the SSH server
	IP                 string `json:"ip"`                   // IP address of the client that established the connection
	LastBytesSent      int64  `json:"last_bytes_sent"`      // Number of bytes sent in the last session from client to destination (upload)
	LastBytesReceived  int64  `json:"last_bytes_received"`  // Number of bytes received in the last session from destination to client (download)
	LastBytesTotal     int64  `json:"last_bytes_total"`     // Total bytes (sent + received) in the last session
	TotalBytesSent     int64  `json:"total_bytes_sent"`     // Total bytes sent by this user across all sessions
	TotalBytesReceived int64  `json:"total_bytes_received"` // Total bytes received by this user across all sessions
	TotalBytes         int64  `json:"total_bytes"`          // Overall traffic total  (total_bytes_sent + total_bytes_received)
	LastTimestamp      string `json:"last_timestamp"`       // Timestamp of the last session in ISO-8601 format (e.g., "2025-07-05T01:22:58Z")
}

// Change this to "powershell.exe" if needed

// User structure with role-based access control, domain/IP blocking, and logging
type User struct {
	Username       string   `json:"username"`
	Password       string   `json:"password"`
	Role           string   `json:"role"`            // "user" or "admin"
	BlockedDomains []string `json:"blocked_domains"` // List of blocked domains/IPs with wildcard support
	BlockedIPs     []string `json:"blocked_ips"`     // List of blocked IPs with wildcard support
	Log            string   `json:"log"`             // "yes" or "no" - enable/disable user access logging
}

var users map[string]User

type ServerConfig struct {
	Ports           []int  `json:"ports"`
	Shell           string `json:"shell"`
	MaxAuthAttempts int    `json:"max_auth_attempts"`
	ServerVersion   string `json:"server_version"`
}

var serverConfig ServerConfig

type BlockedIPs struct {
	Blocked []string `json:"blocked"`
}

var blockedIPs BlockedIPs
var failedAttempts = make(map[string]int)

func loadUsers(path string) {
	// Get executable directory and use it for file paths
	exeDir, err := SetExecutableDir()
	if err != nil {
		log.Fatalf("Failed to get executable directory: %v", err)
	}
	
	fullPath := filepath.Join(exeDir, path)
	data, err := os.ReadFile(fullPath)
	if err != nil {
		log.Fatalf("Failed to read users file: %v", err)
	}
	
	// Try to parse as new format first (array of User objects)
	var userList []User
	if err := json.Unmarshal(data, &userList); err == nil {
		// New format: array of User objects
		users = make(map[string]User)
		for _, user := range userList {
			users[user.Username] = user
		}
		log.Printf("✅ Loaded %d users with role-based access control", len(users))
		return
	}
	
	// Fallback to old format (map[string]string) for backward compatibility
	var oldUserPass map[string]string
	if err := json.Unmarshal(data, &oldUserPass); err != nil {
		log.Fatalf("Failed to parse users file: %v", err)
	}
	
	// Convert old format to new format with default "user" role
	users = make(map[string]User)
	for username, password := range oldUserPass {
		users[username] = User{
			Username: username,
			Password: password,
			Role:     "user", // Default role for backward compatibility
		}
	}
	log.Printf("✅ Loaded %d users from legacy format (all set to 'user' role)", len(users))
}

func loadServerConfig(path string) {
	// Get executable directory and use it for file paths
	exeDir, err := SetExecutableDir()
	if err != nil {
		log.Fatalf("Failed to get executable directory: %v", err)
	}
	
	fullPath := filepath.Join(exeDir, path)
	data, err := os.ReadFile(fullPath)
	if err != nil {
		log.Fatalf("Failed to read server config file: %v", err)
	}
	err = json.Unmarshal(data, &serverConfig)
	if err != nil {
		log.Fatalf("Failed to parse server config file: %v", err)
	}
}

// start Block IPs

func loadBlockedIPs() {
	// Get executable directory and use it for file paths
	exeDir, err := SetExecutableDir()
	if err != nil {
		log.Printf("Failed to get executable directory: %v", err)
		blockedIPs = BlockedIPs{}
		return
	}
	
	fullPath := filepath.Join(exeDir, "blocked_ips.json")
	data, err := os.ReadFile(fullPath)
	if err != nil {
		blockedIPs = BlockedIPs{}
		return
	}
	_ = json.Unmarshal(data, &blockedIPs)
}

func saveBlockedIPs() {
	// Get executable directory and use it for file paths
	exeDir, err := SetExecutableDir()
	if err != nil {
		log.Printf("Failed to get executable directory: %v", err)
		return
	}
	
	data, _ := json.MarshalIndent(blockedIPs, "", "  ")
	fullPath := filepath.Join(exeDir, "blocked_ips.json")
	_ = os.WriteFile(fullPath, data, 0644)
}

func isBlocked(ip string) bool {
	for _, b := range blockedIPs.Blocked {
		if b == ip {
			return true
		}
	}
	return false
}

// End Block IPs

// Check if a domain/IP is blocked for a specific user
func isDomainOrIPBlocked(username, target string) bool {
	user, exists := users[username]
	if !exists {
		return false
	}

	// Check blocked domains
	for _, blockedDomain := range user.BlockedDomains {
		if matchesWildcard(target, blockedDomain) {
			return true
		}
	}

	// Check blocked IPs
	for _, blockedIP := range user.BlockedIPs {
		if matchesWildcard(target, blockedIP) {
			return true
		}
	}

	return false
}

// Check if a string matches a wildcard pattern
func matchesWildcard(str, pattern string) bool {
	// Handle exact match
	if str == pattern {
		return true
	}

	// Handle wildcard patterns
	if strings.Contains(pattern, "*") {
		// Convert wildcard pattern to regex
		regexPattern := strings.ReplaceAll(pattern, ".", "\\.")
		regexPattern = strings.ReplaceAll(regexPattern, "*", ".*")
		
		// Simple regex matching (you might want to use regexp package for more complex patterns)
		if strings.HasPrefix(regexPattern, ".*") && strings.HasSuffix(regexPattern, ".*") {
			// Pattern like *example.com*
			innerPattern := regexPattern[2 : len(regexPattern)-2]
			return strings.Contains(str, innerPattern)
		} else if strings.HasPrefix(regexPattern, ".*") {
			// Pattern like *.example.com
			suffix := regexPattern[2:]
			return strings.HasSuffix(str, suffix)
		} else if strings.HasSuffix(regexPattern, ".*") {
			// Pattern like example.*
			prefix := regexPattern[:len(regexPattern)-2]
			return strings.HasPrefix(str, prefix)
		}
	}

	return false
}

// Load existing traffic files on startup
func loadExistingTrafficFiles() {
	// Get executable directory and use it for file paths
	exeDir, err := SetExecutableDir()
	if err != nil {
		log.Printf("❌ Failed to get executable directory: %v", err)
		return
	}
	
	// Create users_traffic directory if it doesn't exist
	trafficDir := filepath.Join(exeDir, "users_traffic")
	if err := os.MkdirAll(trafficDir, 0755); err != nil {
		log.Printf("❌ Failed to create users_traffic directory: %v", err)
		return
	}

	// Read all files in users_traffic directory
	files, err := os.ReadDir(trafficDir)
	if err != nil {
		log.Printf("❌ Failed to read users_traffic directory: %v", err)
		return
	}

	loadedCount := 0
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		// Check if file is a traffic file (starts with "traffic_" and ends with ".json")
		filename := file.Name()
		if len(filename) > 13 && filename[:8] == "traffic_" && filename[len(filename)-5:] == ".json" {
			// Extract username from filename
			username := filename[8 : len(filename)-5]
			
			// Read and parse the traffic file
			fullPath := filepath.Join(trafficDir, filename)
			data, err := os.ReadFile(fullPath)
			if err != nil {
				log.Printf("❌ Failed to read traffic file %s: %v", filename, err)
				continue
			}

			var stats TrafficStats
			if err := json.Unmarshal(data, &stats); err != nil {
				log.Printf("❌ Failed to parse traffic file %s: %v", filename, err)
				continue
			}

			// Store in memory
			trafficMap.Store(username, &stats)
			loadedCount++
			
			log.Printf("📊 Loaded traffic data for %s: ↑%dB ↓%dB 📦%dB", 
				username, stats.TotalBytesSent, stats.TotalBytesReceived, stats.TotalBytes)
		}
	}

	if loadedCount > 0 {
		log.Printf("✅ Loaded %d existing traffic files from users_traffic/", loadedCount)
	} else {
		log.Printf("ℹ️  No existing traffic files found in users_traffic/")
	}
}

// Create SSH server config
func createSSHConfig() *ssh.ServerConfig {
	config := &ssh.ServerConfig{
		ServerVersion: serverConfig.ServerVersion,
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			ip, portStr, _ := net.SplitHostPort(c.RemoteAddr().String())
			clientPort := 0
			if portStr != "" {
				fmt.Sscanf(portStr, "%d", &clientPort)
			}
			
			// Extract server port from local address
			_, serverPortStr, _ := net.SplitHostPort(c.LocalAddr().String())
			serverPort := 0
			if serverPortStr != "" {
				fmt.Sscanf(serverPortStr, "%d", &serverPort)
			}
			
			if isBlocked(ip) {
				log.Printf("⛔ Blocked IP tried to connect: %s", ip)
				return nil, fmt.Errorf("your IP is blocked")
			}

			if user, ok := users[c.User()]; ok && user.Password == string(pass) {
				delete(failedAttempts, ip) // reset count
				log.Printf("✅ User %s (%s) authenticated from %s", c.User(), user.Role, ip)
				return nil, nil
			}

			logInvalidLogin(c.User(), string(pass), ip, clientPort, serverPort)
			// افزايش تعداد تلاش ناموفق
			failedAttempts[ip]++
			log.Printf("❌ Failed login from %s (%d attempts)", ip, failedAttempts[ip])

			if failedAttempts[ip] >= serverConfig.MaxAuthAttempts {
				log.Printf("🚫 Blocking IP: %s", ip)
				blockedIPs.Blocked = append(blockedIPs.Blocked, ip)
				saveBlockedIPs()
			}

			return nil, fmt.Errorf("authentication failed")
		},
	}

	privateBytes, err := os.ReadFile("id_rsa")
	if err != nil {
		log.Fatalf("Failed to load private key: %s", err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatalf("Failed to parse private key: %s", err)
	}

	config.AddHostKey(private)
	return config
}

// Handle SSH session using ConPTY
func handleSession(channel ssh.Channel, requests <-chan *ssh.Request, username string) {
	defer channel.Close()
	hasPty := false
	winCh := make(chan *WindowSize, 1)

	// Check if user has admin role for shell access
	user, exists := users[username]
	if !exists {
		channel.Write([]byte("❌ User not found\n"))
		return
	}

	for req := range requests {
		switch req.Type {
		case "pty-req":
			hasPty = true
			if req.WantReply {
				req.Reply(true, nil)
			}

		case "window-change":
			// Handle terminal resize
			if len(req.Payload) >= 16 {
				width := uint32(req.Payload[0])<<24 | uint32(req.Payload[1])<<16 | uint32(req.Payload[2])<<8 | uint32(req.Payload[3])
				height := uint32(req.Payload[4])<<24 | uint32(req.Payload[5])<<16 | uint32(req.Payload[6])<<8 | uint32(req.Payload[7])
				pixelWidth := uint32(req.Payload[8])<<24 | uint32(req.Payload[9])<<16 | uint32(req.Payload[10])<<8 | uint32(req.Payload[11])
				pixelHeight := uint32(req.Payload[12])<<24 | uint32(req.Payload[13])<<16 | uint32(req.Payload[14])<<8 | uint32(req.Payload[15])
				
				select {
				case winCh <- &WindowSize{Width: width, Height: height, PixelWidth: pixelWidth, PixelHeight: pixelHeight}:
				default:
				}
			}
			if req.WantReply {
				req.Reply(true, nil)
			}

		case "shell":
			if !hasPty {
				if req.WantReply {
					req.Reply(false, nil)
				}
				continue
			}
			
			// Check if user has admin role for shell access
			if user.Role != "admin" {
				channel.Write([]byte("❌ Access Denied: Shell access is restricted to admin users only\n"))
				channel.Write([]byte("ℹ️  Your role: " + user.Role + "\n"))
				channel.Write([]byte("ℹ️  You can still use tunneling features\n"))
				if req.WantReply {
					req.Reply(false, nil)
				}
				continue
			}
			
			if req.WantReply {
				req.Reply(true, nil)
			}

			// Custom Shell (only for admin users)
			asciiBanner := `

░█████╗░██████╗░██████╗░░█████╗░██╗░░░░░  ░░██╗██╗██╗██████╗░██████╗░░█████╗░████████╗░█████╗░
██╔══██╗██╔══██╗██╔══██╗██╔══██╗██║░░░░░  ░██╔╝██║██║██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔══██╗
███████║██████╦╝██║░░██║███████║██║░░░░░  ██╔╝░██║██║██████╔╝██████╔╝██║░░██║░░░██║░░░██║░░██║
██╔══██║██╔══██╗██║░░██║██╔══██║██║░░░░░  ███████║██║██╔═══╝░██╔══██╗██║░░██║░░░██║░░░██║░░██║
██║░░██║██████╦╝██████╔╝██║░░██║███████╗  ╚════██║██║██║░░░░░██║░░██║╚█████╔╝░░░██║░░░╚█████╔╝
╚═╝░░╚═╝╚═════╝░╚═════╝░╚═╝░░╚═╝╚══════╝  ░░░░░╚═╝╚═╝╚═╝░░░░░╚═╝░░╚═╝░╚════╝░░░░╚═╝░░░░╚════╝░

░██████╗███████╗██████╗░██╗░░░██╗███████╗██████╗░
██╔════╝██╔════╝██╔══██╗██║░░░██║██╔════╝██╔══██╗
╚█████╗░█████╗░░██████╔╝╚██╗░██╔╝█████╗░░██████╔╝
░╚═══██╗██╔══╝░░██╔══██╗░╚████╔╝░██╔══╝░░██╔══██╗
██████╔╝███████╗██║░░██║░░╚██╔╝░░███████╗██║░░██║
╚═════╝░╚══════╝╚═╝░░╚═╝░░░╚═╝░░░╚══════╝╚═╝░░╚═╝

🛡️  Welcome to Abdal 4iProto Server ver 5.10
🧠  Developed by: Ebrahim Shafiei (EbraSha)
✉️ Prof.Shafiei@Gmail.com

`
			channel.Write([]byte(asciiBanner))

			// Running shell with PTY

			startShell(channel, serverConfig.Shell, winCh)

			return

		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

// Handle a new SSH connection
func handleConnection(conn net.Conn, config *ssh.ServerConfig) {
	// Optional banner before handshake
	conn.Write([]byte("Abdal 4iProto Server\n"))

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		log.Printf("Failed to handshake: %s", err)
		return
	}
	defer sshConn.Close()

	// Track active connection
	connID := fmt.Sprintf("%s-%d", sshConn.RemoteAddr().String(), time.Now().UnixNano())
	activeConnections.Store(connID, sshConn.RemoteAddr().String())
	defer activeConnections.Delete(connID)

	log.Printf("New SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())
	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {

		// Accessing username and IP address
		username := sshConn.User()
		log.Printf("📡 Starting TCP forwarding for user: %s", username)
		userIP, _, _ := net.SplitHostPort(sshConn.RemoteAddr().String())

		// AllowUdpForwarding
		if newChannel.ChannelType() == "direct-udpip" {
			go handleDirectUDPIP(newChannel)
			continue
		}

		// AllowTcpForwarding
		if newChannel.ChannelType() == "direct-tcpip" {
			go handleDirectTCPIP(newChannel, username, userIP)
			log.Printf("⚡ Received direct-tcpip from %s", username)
			continue
		}

		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("Channel accept failed: %v", err)
			continue
		}
		go handleSession(channel, requests, sshConn.User())

	}
}

// Writer that counts how many bytes are written
func countWriter(counter *atomic.Int64) io.Writer {
	pr, pw := io.Pipe()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := pr.Read(buf)
			if err != nil {
				return
			}
			counter.Add(int64(n))
		}
	}()
	return pw
}

func handleDirectTCPIP(newChannel ssh.NewChannel, username string, userIP string) {
	type directTCPIPReq struct {
		HostToConnect     string
		PortToConnect     uint32
		OriginatorAddress string
		OriginatorPort    uint32
	}

	var req directTCPIPReq
	if err := ssh.Unmarshal(newChannel.ExtraData(), &req); err != nil {
		newChannel.Reject(ssh.Prohibited, "could not parse direct-tcpip request")
		return
	}

	target := fmt.Sprintf("%s:%d", req.HostToConnect, req.PortToConnect)
	
	// Check if the target domain/IP is blocked for this user
	if isDomainOrIPBlocked(username, req.HostToConnect) {
		log.Printf("🚫 User %s tried to access blocked target: %s", username, req.HostToConnect)
		logBlockedAccess(username, req.HostToConnect, userIP)
		newChannel.Reject(ssh.Prohibited, "access to this domain/IP is blocked")
		return
	}
	
	// Log user access if logging is enabled for this user
	logUserAccess(username, req.HostToConnect, userIP)
	
	// Create optimized TCP connection
	destConn, err := net.Dial("tcp", target)
	if err != nil {
		newChannel.Reject(ssh.ConnectionFailed, "could not connect to target")
		return
	}
	
	// Optimize TCP connection settings for better performance
	if tcpConn, ok := destConn.(*net.TCPConn); ok {
		// Enable TCP_NODELAY for lower latency
		tcpConn.SetNoDelay(true)
		// Set keep-alive for better connection management
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	channel, requests, err := newChannel.Accept()
	if err != nil {
		destConn.Close()
		return
	}
	go ssh.DiscardRequests(requests)

	var bytesSent atomic.Int64
	var bytesReceived atomic.Int64

	var wg sync.WaitGroup
	wg.Add(2)

	// Optimized buffer sizes for better performance
	const bufferSize = 64 * 1024 // 64KB buffer for better throughput

	// Receive from server → send to client (optimized)
	go func() {
		defer wg.Done()
		defer channel.CloseWrite()
		
		buf := make([]byte, bufferSize)
		totalBytes := int64(0)
		
		for {
			n, err := destConn.Read(buf)
			if n > 0 {
				bytesReceived.Add(int64(n))
				totalBytes += int64(n)
				
				// Write to channel with error handling
				if _, writeErr := channel.Write(buf[:n]); writeErr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		
		log.Printf("📥 %s received %d bytes from %s", username, totalBytes, target)
	}()

	// Send from client → to server (optimized)
	go func() {
		defer wg.Done()
		defer destConn.Close()
		
		buf := make([]byte, bufferSize)
		totalBytes := int64(0)
		
		for {
			n, err := channel.Read(buf)
			if n > 0 {
				bytesSent.Add(int64(n))
				totalBytes += int64(n)
				
				// Write to destination with error handling
				if _, writeErr := destConn.Write(buf[:n]); writeErr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		
		log.Printf("📤 %s sent %d bytes to %s", username, totalBytes, target)
	}()

	wg.Wait()

	// 🧠 After completing send and receive, update values:
	sent := bytesSent.Load()
	received := bytesReceived.Load()

	statsAny, ok := trafficMap.Load(username)
	if !ok {
		// Try to load from existing traffic file
		exeDir, err := SetExecutableDir()
		if err == nil {
			trafficDir := filepath.Join(exeDir, "users_traffic")
			filename := fmt.Sprintf("traffic_%s.json", username)
			fullPath := filepath.Join(trafficDir, filename)
			if data, err := os.ReadFile(fullPath); err == nil {
				var existingStats TrafficStats
				if json.Unmarshal(data, &existingStats) == nil {
					statsAny = &existingStats
					trafficMap.Store(username, statsAny)
					log.Printf("✅ Loaded existing traffic data for %s", username)
				}
			}
		}
		
		// If still not found, create new user stats
		if statsAny == nil {
			statsAny = &TrafficStats{
				Username: username,
				IP:       userIP,
			}
			trafficMap.Store(username, statsAny)
		}
	}
	stats := statsAny.(*TrafficStats)

	// Update session values
	stats.LastBytesSent = sent
	stats.LastBytesReceived = received
	stats.LastBytesTotal = sent + received
	stats.LastTimestamp = time.Now().Format(time.RFC3339)

	// Add to total values (cumulative across all sessions)
	stats.TotalBytesSent += sent
	stats.TotalBytesReceived += received
	stats.TotalBytes = stats.TotalBytesSent + stats.TotalBytesReceived

	log.Printf("🧠 [MEMORY] Updated traffic for %s in RAM - Session: ↑%dB ↓%dB | Total: ↑%dB ↓%dB 📦%dB", 
		username, sent, received, stats.TotalBytesSent, stats.TotalBytesReceived, stats.TotalBytes)

}

// Handle UDP forwarding through SSH with length-prefix framing
func handleDirectUDPIP(newChannel ssh.NewChannel) {
	type directUDPIPReq struct {
		HostToConnect     string
		PortToConnect     uint32
		OriginatorAddress string
		OriginatorPort    uint32
	}

	// Helper functions for length-prefix framing
	readFrame := func(r io.Reader) ([]byte, error) {
		var lb [2]byte
		if _, err := io.ReadFull(r, lb[:]); err != nil {
			return nil, err
		}
		n := int(binary.BigEndian.Uint16(lb[:]))
		if n <= 0 || n > 65535 {
			return nil, fmt.Errorf("bad length")
		}
		b := make([]byte, n)
		_, err := io.ReadFull(r, b)
		return b, err
	}

	writeFrame := func(w io.Writer, payload []byte) error {
		if len(payload) > 65535 {
			return fmt.Errorf("oversize datagram")
		}
		var lb [2]byte
		binary.BigEndian.PutUint16(lb[:], uint16(len(payload)))
		if _, err := w.Write(lb[:]); err != nil {
			return err
		}
		_, err := w.Write(payload)
		return err
	}

	var req directUDPIPReq
	if err := ssh.Unmarshal(newChannel.ExtraData(), &req); err != nil {
		newChannel.Reject(ssh.Prohibited, "bad direct-udpip request")
		return
	}

	// Use net.ResolveUDPAddr for better hostname resolution
	addrStr := net.JoinHostPort(req.HostToConnect, fmt.Sprintf("%d", req.PortToConnect))
	udpAddr, err := net.ResolveUDPAddr("udp", addrStr)
	if err != nil {
		newChannel.Reject(ssh.ConnectionFailed, "resolve failed")
		return
	}

	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		newChannel.Reject(ssh.ConnectionFailed, "udp connect failed")
		return
	}

	channel, requests, err := newChannel.Accept()
	if err != nil {
		udpConn.Close()
		return
	}
	go ssh.DiscardRequests(requests)

	// Set initial deadline for connection management
	_ = udpConn.SetDeadline(time.Now().Add(60 * time.Second))

	// SSH → UDP (with framing)
	go func() {
		defer udpConn.Close()
		defer channel.CloseWrite()
		for {
			payload, err := readFrame(channel)
			if err != nil {
				return
			}
			udpConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := udpConn.Write(payload); err != nil {
				return
			}
		}
	}()

	// UDP → SSH (with framing)
	go func() {
		defer channel.Close()
		buf := make([]byte, 65535) // Maximum UDP packet size
		for {
			udpConn.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, _, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if err := writeFrame(channel, buf[:n]); err != nil {
				return
			}
		}
	}()
}

// logInvalidLogin writes failed login attempts to a log file
func logInvalidLogin(username string, password string, ip string, clientPort int, serverPort int) {
	// Get executable directory and use it for file paths
	exeDir, err := SetExecutableDir()
	if err != nil {
		log.Printf("Failed to get executable directory: %v", err)
		return
	}
	
	logEntry := fmt.Sprintf(
		"[❌ Invalid Login] [%s] IP: %s | Client Port: %d | Server Port: %d | Username: %q | Password: %q\n",
		time.Now().Format("2006-01-02 15:04:05"),
		ip,
		clientPort,
		serverPort,
		username,
		password,
	)

	fullPath := filepath.Join(exeDir, "invalid_logins.log")
	f, err := os.OpenFile(fullPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Failed to open invalid_logins.log: %v", err)
		return
	}
	defer f.Close()

	if _, err := f.WriteString(logEntry); err != nil {
		log.Printf("Failed to write invalid login: %v", err)
	}
}

// logBlockedAccess writes blocked domain/IP access attempts to individual user log files
func logBlockedAccess(username string, target string, userIP string) {
	// Get executable directory and use it for file paths
	exeDir, err := SetExecutableDir()
	if err != nil {
		log.Printf("❌ Failed to get executable directory: %v", err)
		return
	}
	
	// Create blocked_access directory if it doesn't exist
	blockedDir := filepath.Join(exeDir, "blocked_access")
	if err := os.MkdirAll(blockedDir, 0755); err != nil {
		log.Printf("❌ Failed to create blocked_access directory: %v", err)
		return
	}

	// Create log entry
	logEntry := fmt.Sprintf(
		"[🚫 Blocked Access] [%s] Target: %s | User IP: %s\n",
		time.Now().Format("2006-01-02 15:04:05"),
		target,
		userIP,
	)

	// Write to user-specific blocked access log file
	filename := fmt.Sprintf("%s.log", username)
	fullPath := filepath.Join(blockedDir, filename)
	f, err := os.OpenFile(fullPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Failed to open blocked access log file %s: %v", filename, err)
		return
	}
	defer f.Close()

	if _, err := f.WriteString(logEntry); err != nil {
		log.Printf("Failed to write blocked access log: %v", err)
	}
}

// logUserAccess writes user access attempts to individual user log files
func logUserAccess(username string, target string, userIP string) {
	// Check if user logging is enabled
	user, exists := users[username]
	if !exists || user.Log != "yes" {
		return // Skip logging if user doesn't exist or logging is disabled
	}

	// Get executable directory and use it for file paths
	exeDir, err := SetExecutableDir()
	if err != nil {
		log.Printf("❌ Failed to get executable directory: %v", err)
		return
	}

	// Create users_log directory if it doesn't exist
	usersLogDir := filepath.Join(exeDir, "users_log")
	if err := os.MkdirAll(usersLogDir, 0755); err != nil {
		log.Printf("❌ Failed to create users_log directory: %v", err)
		return
	}

	// Create log entry
	logEntry := fmt.Sprintf(
		"[📡 User Access] [%s] Target: %s | User IP: %s\n",
		time.Now().Format("2006-01-02 15:04:05"),
		target,
		userIP,
	)

	// Write to user-specific log file
	filename := fmt.Sprintf("%s.log", username)
	fullPath := filepath.Join(usersLogDir, filename)
	f, err := os.OpenFile(fullPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Failed to open user log file %s: %v", filename, err)
		return
	}
	defer f.Close()

	if _, err := f.WriteString(logEntry); err != nil {
		log.Printf("Failed to write user access log: %v", err)
	}
}

// startServer starts the server (used by Windows service)
func startServer() {
	// Load configuration files
	loadUsers("users.json")
	loadServerConfig("server_config.json")
	loadBlockedIPs()
	
	// Load existing traffic files to preserve traffic statistics across restarts
	loadExistingTrafficFiles()

	for _, port := range serverConfig.Ports {
		go func(p int) {
			listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", p))
			if err != nil {
				log.Printf("❌ Failed to listen on port %d: %v", p, err)
				return
			}
			defer listener.Close()

			log.Printf("🚀 Abdal 4iProto Server listening on port %d", p)

			for {
				conn, err := listener.Accept()
				if err != nil {
					log.Printf("❌ Failed to accept connection on port %d: %v", p, err)
					continue
				}

				// Optimize TCP connection settings for better performance
				if tcpConn, ok := conn.(*net.TCPConn); ok {
					// Enable TCP_NODELAY for lower latency
					tcpConn.SetNoDelay(true)
					// Set keep-alive for better connection management
					tcpConn.SetKeepAlive(true)
					tcpConn.SetKeepAlivePeriod(30 * time.Second)
				}

				go handleConnection(conn, createSSHConfig())
			}
		}(port)
	}

	go func() {
		// Get executable directory and use it for file paths
		exeDir, err := SetExecutableDir()
		if err != nil {
			log.Printf("❌ Failed to get executable directory: %v", err)
			return
		}
		
		// Create users_traffic directory if it doesn't exist
		trafficDir := filepath.Join(exeDir, "users_traffic")
		if err := os.MkdirAll(trafficDir, 0755); err != nil {
			log.Printf("❌ Failed to create users_traffic directory: %v", err)
		}

		for {
			time.Sleep(10 * time.Second)
			trafficMap.Range(func(key, value any) bool {
				username := key.(string)
				stats := value.(*TrafficStats)

				// Just save the current totals - no need to calculate differences
				// since totals are already being updated in handleDirectTCPIP
				filename := fmt.Sprintf("traffic_%s.json", username)
				fullPath := filepath.Join(trafficDir, filename)
				data, err := json.MarshalIndent(stats, "", "  ")
				if err != nil {
					log.Printf("❌ Failed to marshal %s: %v", username, err)
					return true
				}
				err = os.WriteFile(fullPath, data, 0644)
				if err != nil {
					log.Printf("❌ Failed to write traffic file for %s: %v", username, err)
					return true
				}

				log.Printf("✅ [AUTO] Saved traffic → %s | ↑%dB ↓%dB 📦 %dB",
					filename, stats.TotalBytesSent, stats.TotalBytesReceived, stats.TotalBytes)

				return true
			})
		}
	}()

	// Debug
	go func() {
		for {
			time.Sleep(30 * time.Second)
			log.Printf("🔍 [DEBUG] Active connections: %d", getActiveConnectionsCount())
			log.Printf("🔍 [DEBUG] Traffic map entries: %d", getTrafficMapSize())
		}
	}()

	// Keep the server running
	select {}
}

// Main entry point
func main() {
	// Check for Windows service commands first
	if HandleServiceCommands() {
		return // Exit if service command was handled
	}

	// Run as regular application
	startServer()
}
