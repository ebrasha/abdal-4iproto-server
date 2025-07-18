// Programmer       : Ebrahim Shafiei (EbraSha)
// Email            : Prof.Shafiei@Gmail.com

package main

import (
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

var trafficMap sync.Map // key: username, value: *TrafficStats

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
	LastSavedSent      int64  `json:"-"`                    // Stored value of last sent bytes for internal comparison
	LastSavedReceived  int64  `json:"-"`                    // Stored value of last received bytes for internal comparison
}

// Change this to "powershell.exe" if needed

var userPass map[string]string

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
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("Failed to read users file: %v", err)
	}
	err = json.Unmarshal(data, &userPass)
	if err != nil {
		log.Fatalf("Failed to parse users file: %v", err)
	}
}

func loadServerConfig(path string) {
	data, err := os.ReadFile(path)
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
	data, err := os.ReadFile("blocked_ips.json")
	if err != nil {
		blockedIPs = BlockedIPs{}
		return
	}
	_ = json.Unmarshal(data, &blockedIPs)
}

func saveBlockedIPs() {
	data, _ := json.MarshalIndent(blockedIPs, "", "  ")
	_ = os.WriteFile("blocked_ips.json", data, 0644)
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

// Create SSH server config
func createSSHConfig() *ssh.ServerConfig {
	config := &ssh.ServerConfig{
		ServerVersion: serverConfig.ServerVersion,
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			ip, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			if isBlocked(ip) {
				log.Printf("⛔ Blocked IP tried to connect: %s", ip)
				return nil, fmt.Errorf("your IP is blocked")
			}

			if p, ok := userPass[c.User()]; ok && p == string(pass) {
				delete(failedAttempts, ip) // reset count
				return nil, nil
			}

			logInvalidLogin(c.User(), string(pass), ip)
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
func handleSession(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()
	hasPty := false

	for req := range requests {
		switch req.Type {
		case "pty-req":
			hasPty = true
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
			if req.WantReply {
				req.Reply(true, nil)
			}

			// Custom Shell
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

🛡️  Welcome to Abdal 4iProto Server
🧠  Created by: Ebrahim Shafiei (EbraSha)
✉️ Prof.Shafiei@Gmail.com

`
			channel.Write([]byte(asciiBanner))

			// Running shell with ConPTY

			startShell(channel, serverConfig.Shell)

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
		go handleSession(channel, requests)

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
	destConn, err := net.Dial("tcp", target)
	if err != nil {
		newChannel.Reject(ssh.ConnectionFailed, "could not connect to target")
		return
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

	// Receive from server → send to client
	go func() {
		defer wg.Done()
		n, _ := io.Copy(channel, io.TeeReader(destConn, countWriter(&bytesReceived)))
		_ = channel.CloseWrite()
		log.Printf("📥 %s received %d bytes from %s", username, n, target)
	}()

	// Send from client → to server
	go func() {
		defer wg.Done()
		n, _ := io.Copy(destConn, io.TeeReader(channel, countWriter(&bytesSent)))
		_ = destConn.Close()
		log.Printf("📤 %s sent %d bytes to %s", username, n, target)
	}()

	wg.Wait()

	// 🧠 After completing send and receive, update values:
	sent := bytesSent.Load()
	received := bytesReceived.Load()

	statsAny, ok := trafficMap.Load(username)
	if !ok {
		statsAny = &TrafficStats{
			Username: username,
			IP:       userIP,
		}
		trafficMap.Store(username, statsAny)
	}
	stats := statsAny.(*TrafficStats)

	stats.LastBytesSent = sent
	stats.LastBytesReceived = received
	stats.LastBytesTotal = sent + received
	stats.TotalBytesSent += sent
	stats.TotalBytesReceived += received
	stats.TotalBytes = stats.TotalBytesSent + stats.TotalBytesReceived
	stats.LastTimestamp = time.Now().Format(time.RFC3339)

	// Save for comparison next time
	stats.LastSavedSent = sent
	stats.LastSavedReceived = received

	log.Printf("🧠 [MEMORY] Updated traffic for %s in RAM", username)

}

// Handle UDP forwarding through SSH
func handleDirectUDPIP(newChannel ssh.NewChannel) {
	type directUDPIPReq struct {
		HostToConnect     string
		PortToConnect     uint32
		OriginatorAddress string
		OriginatorPort    uint32
	}

	var req directUDPIPReq
	if err := ssh.Unmarshal(newChannel.ExtraData(), &req); err != nil {
		newChannel.Reject(ssh.Prohibited, "could not parse direct-udpip request")
		return
	}

	targetAddr := &net.UDPAddr{
		IP:   net.ParseIP(req.HostToConnect),
		Port: int(req.PortToConnect),
	}

	udpConn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		newChannel.Reject(ssh.ConnectionFailed, "could not connect to UDP target")
		return
	}

	channel, requests, err := newChannel.Accept()
	if err != nil {
		udpConn.Close()
		return
	}

	go ssh.DiscardRequests(requests)

	// SSH → UDP
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := channel.Read(buf)
			if err != nil {
				break
			}
			udpConn.Write(buf[:n])
		}
	}()

	// UDP → SSH
	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				break
			}
			channel.Write(buf[:n])
		}
	}()
}

// logInvalidLogin writes failed login attempts to a log file
func logInvalidLogin(username string, password string, ip string) {
	logEntry := fmt.Sprintf(
		"[❌ Invalid Login] [%s] IP: %s | Username: %q | Password: %q\n",
		time.Now().Format("2006-01-02 15:04:05"),
		ip,
		username,
		password,
	)

	f, err := os.OpenFile("invalid_logins.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Failed to open invalid_logins.log: %v", err)
		return
	}
	defer f.Close()

	if _, err := f.WriteString(logEntry); err != nil {
		log.Printf("Failed to write invalid login: %v", err)
	}
}

// Main entry point
func main() {
	// Load configuration files
	loadUsers("users.json")
	loadServerConfig("server_config.json")
	loadBlockedIPs()

	for _, port := range serverConfig.Ports {
		go func(p int) {
			listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", p))
			if err != nil {
				log.Fatalf("Listen error on port %d: %v", p, err)
			}
			log.Printf("🔒 Abdal 4iProto Server listening on port %d", p)

			for {
				conn, err := listener.Accept()
				if err != nil {
					log.Printf("Accept error: %v", err)
					continue
				}
				go handleConnection(conn, createSSHConfig())
			}
		}(port)
	}

	go func() {
		for {
			time.Sleep(10 * time.Second)
			trafficMap.Range(func(key, value any) bool {
				username := key.(string)
				stats := value.(*TrafficStats)

				// Precise calculation of difference relative to last save
				newSent := stats.LastBytesSent - stats.LastSavedSent
				newReceived := stats.LastBytesReceived - stats.LastSavedReceived
				if newSent < 0 {
					newSent = 0
				}
				if newReceived < 0 {
					newReceived = 0
				}

				stats.TotalBytesSent += newSent
				stats.TotalBytesReceived += newReceived
				stats.TotalBytes = stats.TotalBytesSent + stats.TotalBytesReceived
				stats.LastSavedSent = stats.LastBytesSent
				stats.LastSavedReceived = stats.LastBytesReceived

				filename := fmt.Sprintf("traffic_%s.json", username)
				data, err := json.MarshalIndent(stats, "", "  ")
				if err != nil {
					log.Printf("❌ Failed to marshal %s: %v", username, err)
					return true
				}
				err = os.WriteFile(filename, data, 0644)
				if err != nil {
					log.Printf("❌ Failed to write traffic file for %s: %v", username, err)
					return true
				}

				log.Printf("✅ [AUTO] Saved traffic → %s | Δ↑%dB Δ↓%dB 📦 %dB",
					filename, newSent, newReceived, stats.TotalBytes)

				return true
			})
		}
	}()

	// Debug
	go func() {
		for {
			time.Sleep(30 * time.Second)
			log.Println("📊 Current in-memory trafficMap state:")
			trafficMap.Range(func(key, value any) bool {
				stats := value.(*TrafficStats)
				log.Printf("→ %s | ↑%d ↓%d Total=%d", stats.Username, stats.TotalBytesSent, stats.TotalBytesReceived, stats.TotalBytes)
				return true
			})
		}
	}()

	select {}
}
