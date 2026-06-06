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
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/time/rate"
)

var trafficMap sync.Map        // key: username, value: *TrafficStats
var activeConnections sync.Map // key: connection ID, value: connection info

// Session metadata storage: sessionID -> connection metadata for session management
var sessionMetadata sync.Map // key: sessionID, value: sessionInfo (username, ip, etc.)

// Rate limiters per user: username -> *rate.Limiter
var rateLimiters sync.Map // key: username, value: *rate.Limiter

// Cached executable directory to avoid repeated os.Executable / os.Chdir calls
// which cause global-state races and unnecessary syscall churn under load.
var (
	cachedExeDir  string
	cachedExeErr  error
	exeDirOnce    sync.Once
)

// SetExecutableDir returns (and on first call, sets) the executable directory.
// The chdir and symlink resolution happen exactly once for the lifetime of the
// process. Subsequent calls are cheap and goroutine-safe.
func SetExecutableDir() (string, error) {
	exeDirOnce.Do(func() {
		exePath, err := os.Executable()
		if err != nil {
			cachedExeErr = fmt.Errorf("failed to get executable path: %w", err)
			return
		}

		exePath, err = filepath.EvalSymlinks(exePath)
		if err != nil {
			cachedExeErr = fmt.Errorf("failed to resolve symlinks: %w", err)
			return
		}

		dir := filepath.Dir(exePath)
		if err := os.Chdir(dir); err != nil {
			cachedExeErr = fmt.Errorf("failed to change working directory: %w", err)
			return
		}
		cachedExeDir = dir
	})
	return cachedExeDir, cachedExeErr
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
	Username          string   `json:"username"`
	Password          string   `json:"password"`
	Role              string   `json:"role"`                // "user" or "admin"
	BlockedDomains    []string `json:"blocked_domains"`     // List of blocked domains/IPs with wildcard support
	BlockedIPs        []string `json:"blocked_ips"`         // List of blocked IPs with wildcard support
	Log               string   `json:"log"`                 // "yes" or "no" - enable/disable user access logging
	MaxSessions       int      `json:"max_sessions"`        // Maximum number of concurrent sessions (default: 2)
	SessionTTLSeconds int      `json:"session_ttl_seconds"` // Session TTL in seconds (default: 300)
	MaxSpeedKBPS      int      `json:"max_speed_kbps"`      // Maximum speed in KB/s (0 = unlimited, default: 0)
	MaxTotalMB        int      `json:"max_total_mb"`        // Maximum total traffic in MB (0 = unlimited, default: 0)
}

var users map[string]User

type ServerConfig struct {
	Ports           []int  `json:"ports"`
	Shell           string `json:"shell"`
	MaxAuthAttempts int    `json:"max_auth_attempts"`
	ServerVersion   string `json:"server_version"`
	PrivateKeyFile  string `json:"private_key_file"` // Path to private key file (default: "id_rsa")
	PublicKeyFile   string `json:"public_key_file"`  // Path to public key file (default: "id_rsa.pub")
	DNSTTEnabled    bool   `json:"dnstt_enabled"`    // Enable DNSTT gateway
	DNSTTListen     string `json:"dnstt_listen"`     // DNSTT listen address (e.g., ":53")
	DNSTTResolver   string `json:"dnstt_resolver"`   // DNSTT resolver address (e.g., "8.8.8.8")
	DNSTTNameserver string `json:"dnstt_nameserver"` // DNSTT nameserver domain (e.g., "dns.example.com")
	DNSTTPublicKey  string `json:"dnstt_public_key"` // (Deprecated/reserved) legacy DNSTT public key field

	// DNSTTPSK is the pre-shared key used to authenticate the OPEN message of a
	// DNS tunnel session (HMAC-SHA256). Empty = gateway open to anyone.
	DNSTTPSK string `json:"dnstt_psk"`
	// DNSTTMaxSessionsPerIP caps concurrent DNS tunnel sessions per client IP
	// (anti-abuse). 0 = unlimited.
	DNSTTMaxSessionsPerIP int `json:"dnstt_max_sessions_per_ip"`
	// DNSTTIdleTimeoutSec closes a DNS tunnel session after this many seconds
	// without any traffic. <= 0 falls back to 60 seconds.
	DNSTTIdleTimeoutSec int `json:"dnstt_idle_timeout_seconds"`
}

var serverConfig ServerConfig

type BlockedIPs struct {
	Blocked []string `json:"blocked"`
}

// blockedIPs holds the canonical on-disk slice form for serialization.
// blockedIPsSet provides O(1) thread-safe lookups for hot-path checks.
// Both are kept in sync under blockedIPsMu.
var (
	blockedIPs    BlockedIPs
	blockedIPsSet = make(map[string]struct{})
	blockedIPsMu  sync.RWMutex
)

// failedAttempts tracks failed auth counts per IP. Access is protected by
// failedAttemptsMu to avoid concurrent map writes under brute-force load.
var (
	failedAttempts   = make(map[string]int)
	failedAttemptsMu sync.Mutex
)

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
			// Set default values if not specified
			if user.MaxSessions <= 0 {
				user.MaxSessions = 2 // Default max sessions
			}
			if user.SessionTTLSeconds <= 0 {
				user.SessionTTLSeconds = 300 // Default TTL: 5 minutes (300 seconds)
			}
			if user.MaxTotalMB < 0 {
				user.MaxTotalMB = 0 // Default: unlimited (0 means no limit)
			}
			users[user.Username] = user

			// Initialize rate limiter for user if MaxSpeedKBPS is set
			if user.MaxSpeedKBPS > 0 {
				initRateLimiter(user.Username, user.MaxSpeedKBPS)
			}
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
			Username:          username,
			Password:          password,
			Role:              "user", // Default role for backward compatibility
			MaxSessions:       2,      // Default max sessions
			SessionTTLSeconds: 300,    // Default TTL: 5 minutes
			MaxTotalMB:        0,      // Default: unlimited
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
		blockedIPsMu.Lock()
		blockedIPs = BlockedIPs{}
		blockedIPsSet = make(map[string]struct{})
		blockedIPsMu.Unlock()
		return
	}

	fullPath := filepath.Join(exeDir, "blocked_ips.json")
	data, err := os.ReadFile(fullPath)

	blockedIPsMu.Lock()
	defer blockedIPsMu.Unlock()

	if err != nil {
		blockedIPs = BlockedIPs{}
		blockedIPsSet = make(map[string]struct{})
		return
	}

	_ = json.Unmarshal(data, &blockedIPs)

	// Rebuild the fast-lookup set, deduplicating any legacy duplicates.
	newSet := make(map[string]struct{}, len(blockedIPs.Blocked))
	uniq := blockedIPs.Blocked[:0]
	for _, ip := range blockedIPs.Blocked {
		if _, ok := newSet[ip]; ok {
			continue
		}
		newSet[ip] = struct{}{}
		uniq = append(uniq, ip)
	}
	blockedIPs.Blocked = uniq
	blockedIPsSet = newSet
}

// saveBlockedIPs persists the blocked IP list. Caller must NOT hold blockedIPsMu.
func saveBlockedIPs() {
	exeDir, err := SetExecutableDir()
	if err != nil {
		log.Printf("Failed to get executable directory: %v", err)
		return
	}

	blockedIPsMu.RLock()
	data, _ := json.MarshalIndent(blockedIPs, "", "  ")
	blockedIPsMu.RUnlock()

	fullPath := filepath.Join(exeDir, "blocked_ips.json")
	_ = os.WriteFile(fullPath, data, 0644)
}

// isBlocked performs an O(1) thread-safe lookup against the in-memory set.
func isBlocked(ip string) bool {
	blockedIPsMu.RLock()
	_, ok := blockedIPsSet[ip]
	blockedIPsMu.RUnlock()
	return ok
}

// addBlockedIP adds an IP to the block list (deduplicated) and persists it
// asynchronously. Returns true if the IP was newly added.
func addBlockedIP(ip string) bool {
	blockedIPsMu.Lock()
	if _, ok := blockedIPsSet[ip]; ok {
		blockedIPsMu.Unlock()
		return false
	}
	blockedIPsSet[ip] = struct{}{}
	blockedIPs.Blocked = append(blockedIPs.Blocked, ip)
	blockedIPsMu.Unlock()

	// Persist outside the lock to avoid holding it during disk IO.
	go saveBlockedIPs()
	return true
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

// initRateLimiter initializes a rate limiter for a user
func initRateLimiter(username string, maxSpeedKBPS int) {
	if maxSpeedKBPS <= 0 {
		return // No rate limiting
	}

	// Convert KB/s to bytes per second
	bytesPerSecond := rate.Limit(maxSpeedKBPS * 1024)

	// Create rate limiter with burst of 1KB (to allow small packets)
	burst := maxSpeedKBPS * 1024 // 1 second worth of bytes
	if burst > 1024*1024 {
		burst = 1024 * 1024 // Max 1MB burst
	}

	limiter := rate.NewLimiter(bytesPerSecond, burst)
	rateLimiters.Store(username, limiter)

	log.Printf("⚡ Rate limiter initialized for %s: %d KB/s (burst: %d bytes)", username, maxSpeedKBPS, burst)
}

// getUserRateLimiter returns the rate limiter for a user (nil if unlimited)
func getUserRateLimiter(username string) *rate.Limiter {
	if limiter, ok := rateLimiters.Load(username); ok {
		return limiter.(*rate.Limiter)
	}
	return nil // No rate limiting
}

// throttledReader wraps an io.Reader with rate limiting
type throttledReader struct {
	r        io.Reader
	limiter  *rate.Limiter
	username string
}

func (tr *throttledReader) Read(p []byte) (n int, err error) {
	if tr.limiter == nil {
		return tr.r.Read(p)
	}

	// Read data
	n, err = tr.r.Read(p)
	if n <= 0 {
		return n, err
	}

	// Wait for rate limiter to allow this amount of data
	err = tr.limiter.WaitN(context.Background(), n)
	if err != nil {
		return n, err
	}

	return n, err
}

// throttledWriter wraps an io.Writer with rate limiting
type throttledWriter struct {
	w        io.Writer
	limiter  *rate.Limiter
	username string
}

func (tw *throttledWriter) Write(p []byte) (n int, err error) {
	if tw.limiter == nil {
		return tw.w.Write(p)
	}

	// Wait for rate limiter to allow this amount of data
	err = tw.limiter.WaitN(context.Background(), len(p))
	if err != nil {
		return 0, err
	}

	// Write data
	return tw.w.Write(p)
}

// checkUserTrafficLimit checks if user has exceeded their maximum traffic limit
// Reads from memory (trafficMap) first, then from file if not in memory
// Returns error if limit exceeded, nil otherwise
func checkUserTrafficLimit(username string, maxTotalMB int) error {
	// If no limit is set (0 or negative), allow access
	if maxTotalMB <= 0 {
		return nil
	}

	var stats *TrafficStats
	var ok bool
	var statsAny interface{}

	// First, try to get traffic stats from memory (real-time)
	statsAny, ok = trafficMap.Load(username)
	if ok {
		stats = statsAny.(*TrafficStats)
	} else {
		// If not in memory, try to load from file (for persistence across restarts)
		exeDir, err := SetExecutableDir()
		if err == nil {
			trafficDir := filepath.Join(exeDir, "users_traffic")
			filename := fmt.Sprintf("traffic_%s.json", username)
			fullPath := filepath.Join(trafficDir, filename)

			// Check if traffic file exists
			if _, err := os.Stat(fullPath); err == nil {
				// File exists, read it
				data, err := os.ReadFile(fullPath)
				if err == nil {
					var fileStats TrafficStats
					if json.Unmarshal(data, &fileStats) == nil {
						stats = &fileStats
						// Store in memory for future use
						trafficMap.Store(username, stats)
					}
				}
			}
		}

		// If still not found, user hasn't used any traffic yet, allow access
		if stats == nil {
			return nil
		}
	}

	// Convert maxTotalMB to bytes (MB to bytes: MB * 1024 * 1024)
	maxTotalBytes := int64(maxTotalMB) * 1024 * 1024

	// Check if total_bytes exceeds limit
	if stats.TotalBytes >= maxTotalBytes {
		log.Printf("🚫 User %s exceeded traffic limit: %d bytes (limit: %d MB = %d bytes)",
			username, stats.TotalBytes, maxTotalMB, maxTotalBytes)
		return fmt.Errorf("traffic limit exceeded: you have used %d MB (limit: %d MB). please contact administrator",
			stats.TotalBytes/(1024*1024), maxTotalMB)
	}

	return nil
}

// TrafficStatsMutex is a mutex-protected wrapper for TrafficStats
type TrafficStatsMutex struct {
	Stats *TrafficStats
	mu    sync.RWMutex
}

var trafficStatsMutexMap sync.Map // key: username, value: *TrafficStatsMutex

// updateTrafficStatsRealTime updates traffic stats in memory and checks limit in real-time
// Returns true if limit exceeded (connection should be closed), false otherwise
func updateTrafficStatsRealTime(username string, userIP string, sent int64, received int64, maxTotalMB int) bool {
	// Get or create traffic stats mutex
	statsMutexAny, ok := trafficStatsMutexMap.Load(username)
	if !ok {
		// Try to load from existing traffic file
		var existingStats *TrafficStats
		exeDir, err := SetExecutableDir()
		if err == nil {
			trafficDir := filepath.Join(exeDir, "users_traffic")
			filename := fmt.Sprintf("traffic_%s.json", username)
			fullPath := filepath.Join(trafficDir, filename)
			if data, err := os.ReadFile(fullPath); err == nil {
				var stats TrafficStats
				if json.Unmarshal(data, &stats) == nil {
					existingStats = &stats
				}
			}
		}

		// If still not found, create new user stats
		if existingStats == nil {
			existingStats = &TrafficStats{
				Username: username,
				IP:       userIP,
			}
		}

		// Store in both maps
		statsMutexAny = &TrafficStatsMutex{Stats: existingStats}
		trafficStatsMutexMap.Store(username, statsMutexAny)
		trafficMap.Store(username, existingStats)
	}

	statsMutex := statsMutexAny.(*TrafficStatsMutex)

	// Lock for writing
	statsMutex.mu.Lock()
	defer statsMutex.mu.Unlock()

	stats := statsMutex.Stats

	// Update total values (cumulative across all sessions)
	stats.TotalBytesSent += sent
	stats.TotalBytesReceived += received
	stats.TotalBytes = stats.TotalBytesSent + stats.TotalBytesReceived
	stats.LastTimestamp = time.Now().Format(time.RFC3339)

	// Also update trafficMap for consistency
	trafficMap.Store(username, stats)

	// Check limit in real-time
	if maxTotalMB > 0 {
		maxTotalBytes := int64(maxTotalMB) * 1024 * 1024
		if stats.TotalBytes >= maxTotalBytes {
			log.Printf("🚫 User %s exceeded traffic limit: %d bytes (limit: %d MB = %d bytes)",
				username, stats.TotalBytes, maxTotalMB, maxTotalBytes)
			return true // Limit exceeded, connection should be closed
		}
	}

	return false // Within limit
}

// saveTrafficStatsToFile saves traffic stats to file (can be called periodically)
func saveTrafficStatsToFile(username string) {
	statsAny, ok := trafficMap.Load(username)
	if !ok {
		return // No stats to save
	}

	stats := statsAny.(*TrafficStats)

	// Get executable directory
	exeDir, err := SetExecutableDir()
	if err != nil {
		log.Printf("⚠️ Failed to get executable directory for saving traffic: %v", err)
		return
	}

	// Create users_traffic directory if it doesn't exist
	trafficDir := filepath.Join(exeDir, "users_traffic")
	if err := os.MkdirAll(trafficDir, 0755); err != nil {
		log.Printf("⚠️ Failed to create users_traffic directory: %v", err)
		return
	}

	// Save to file
	filename := fmt.Sprintf("traffic_%s.json", username)
	fullPath := filepath.Join(trafficDir, filename)
	data, err := json.MarshalIndent(stats, "", "  ")
	if err != nil {
		log.Printf("⚠️ Failed to marshal traffic stats for %s: %v", username, err)
		return
	}

	if err := os.WriteFile(fullPath, data, 0644); err != nil {
		log.Printf("⚠️ Failed to write traffic file for %s: %v", username, err)
		return
	}
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

// cachedSSHConfig stores the single shared *ssh.ServerConfig used by every
// accepted connection. Building this struct involves reading and parsing the
// host private key (an expensive crypto operation) so it MUST be built once
// at startup, not per-connection.
var cachedSSHConfig *ssh.ServerConfig

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
				// Reset failed attempts counter atomically
				failedAttemptsMu.Lock()
				delete(failedAttempts, ip)
				failedAttemptsMu.Unlock()

				// Check traffic limit before allowing authentication
				if err := checkUserTrafficLimit(c.User(), user.MaxTotalMB); err != nil {
					log.Printf("🚫 User %s from %s rejected: traffic limit exceeded", c.User(), ip)
					return nil, err // Return the error message to user
				}

				// Get session manager
				sm := GetSessionManager()

				// Get client version (before handshake, we don't have full metadata yet)
				// We'll use IP and username for now, and update with client version in handleConnection
				clientVersion := "SSH-2.0-Unknown" // Will be updated in handleConnection

				// Create session
				sessionID, err := sm.CreateSession(c.User(), ip, clientVersion)
				if err != nil {
					log.Printf("🚫 Failed to create session for %s from %s: %v", c.User(), ip, err)
					return nil, err // Return the actual error message to user
				}

				// Store sessionID in memory for later use in handleConnection
				sessionMetadata.Store(c.User()+"|"+ip, sessionID)

				log.Printf("✅ User %s (%s) authenticated from %s [Session: %s]", c.User(), user.Role, ip, sessionID[:16]+"...")

				// Return sessionID in permissions for later retrieval
				perms := &ssh.Permissions{
					Extensions: map[string]string{
						"session_id": sessionID,
					},
				}
				return perms, nil
			}

			logInvalidLogin(c.User(), string(pass), ip, clientPort, serverPort)

			// Increment failed attempts under lock; release before any IO
			failedAttemptsMu.Lock()
			failedAttempts[ip]++
			attempts := failedAttempts[ip]
			shouldBlock := attempts >= serverConfig.MaxAuthAttempts
			if shouldBlock {
				// Free the counter slot once the IP is going on the block list.
				delete(failedAttempts, ip)
			}
			failedAttemptsMu.Unlock()

			log.Printf("❌ Failed login from %s (%d attempts)", ip, attempts)

			if shouldBlock {
				if addBlockedIP(ip) {
					log.Printf("🚫 Blocking IP: %s", ip)
				}
			}

			return nil, fmt.Errorf("authentication failed")
		},
	}

	// Configure SSH algorithms for better performance
	config.Config = ssh.Config{
		Ciphers: []string{
			"chacha20-poly1305@openssh.com", // Fast & secure
			"aes128-gcm@openssh.com",        // Lightweight
			"aes256-ctr",                    // Compatibility for older clients
			"aes192-ctr",
			"aes128-ctr",
		},
		KeyExchanges: []string{
			"curve25519-sha256",           // Extremely Fast
			"diffie-hellman-group14-sha1", // Compatible fallback
		},
		MACs: []string{
			"hmac-sha2-256-etm@openssh.com", // Secure
			"hmac-sha2-256",                 // Compatibility
			"hmac-sha1",                     // Fallback for old clients
		},
	}

	// Get private key file path from config (default to "id_rsa" if not specified)
	privateKeyFile := serverConfig.PrivateKeyFile
	if privateKeyFile == "" {
		privateKeyFile = "id_rsa"
	}

	// Get executable directory for relative paths
	exeDir, err := SetExecutableDir()
	if err != nil {
		log.Fatalf("Failed to get executable directory: %v", err)
	}

	// Resolve full path to private key file
	privateKeyPath := filepath.Join(exeDir, privateKeyFile)

	privateBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		log.Fatalf("Failed to load private key from %s: %s", privateKeyPath, err)
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

🛡️  Welcome to Abdal 4iProto Server ver 8.20
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
	// Fast-path reject for already-blocked IPs BEFORE the expensive SSH
	// handshake (key exchange, cipher init, ...). Without this, every attacker
	// connection — even from a known-blocked IP — forces a full crypto
	// negotiation, which is the main reason RAM/CPU spikes during attacks.
	if remoteIP, _, splitErr := net.SplitHostPort(conn.RemoteAddr().String()); splitErr == nil {
		if isBlocked(remoteIP) {
			conn.Close()
			return
		}
	}

	// Optional banner before handshake
	conn.Write([]byte("Abdal 4iProto Server\n"))

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		log.Printf("Failed to handshake: %s", err)
		return
	}
	defer sshConn.Close()

	// Get session manager
	sm := GetSessionManager()

	// Extract sessionID from permissions (set during PasswordCallback)
	username := sshConn.User()
	userIP, _, _ := net.SplitHostPort(sshConn.RemoteAddr().String())
	clientVersionBytes := sshConn.ClientVersion()
	clientVersion := string(clientVersionBytes)

	var sessionID string
	// Try to get sessionID from permissions first
	perms := sshConn.Permissions
	if perms != nil && perms.Extensions != nil {
		if sid, ok := perms.Extensions["session_id"]; ok {
			sessionID = sid
		}
	}

	// If not found in permissions, fall back to the metadata map (legacy path).
	// Either way, we always remove the entry afterwards to prevent the map from
	// growing unbounded across reconnects.
	metaKey := username + "|" + userIP
	if sessionID == "" {
		if sid, ok := sessionMetadata.Load(metaKey); ok {
			sessionID = sid.(string)
		}
	}
	sessionMetadata.Delete(metaKey)

	// Validate session if sessionID exists
	if sessionID != "" {
		// Check if session is valid
		if !sm.IsSessionValid(sessionID) {
			log.Printf("🔒 Invalid or expired session for user %s from %s, closing connection", username, userIP)
			return // Connection will be closed by defer
		}

		// Register connection with session manager
		sm.RegisterConnection(sessionID, sshConn)

		// Update client version (was unknown during PasswordCallback)
		if err := sm.UpdateSessionClientVersion(sessionID, clientVersion); err != nil {
			log.Printf("⚠️ Failed to update session client version: %v", err)
		}

		// Update last seen
		if err := sm.UpdateSessionLastSeen(sessionID); err != nil {
			log.Printf("⚠️ Failed to update session last seen: %v", err)
		}

		// Unregister on connection close
		defer func() {
			sm.UnregisterConnection(sessionID)
			sm.CloseSession(sessionID)
		}()

		log.Printf("🔐 Session validated: %s for user %s from %s", sessionID[:16]+"...", username, userIP)
	} else {
		log.Printf("⚠️ No sessionID found for user %s from %s, connection may not be tracked", username, userIP)
	}

	// Track active connection
	connID := fmt.Sprintf("%s-%d", sshConn.RemoteAddr().String(), time.Now().UnixNano())
	activeConnections.Store(connID, sshConn.RemoteAddr().String())
	defer activeConnections.Delete(connID)

	log.Printf("New SSH connection from %s (%s)", sshConn.RemoteAddr(), clientVersion)
	go ssh.DiscardRequests(reqs)

	// Start periodic session last seen update if session exists.
	// The done channel ensures this goroutine exits as soon as handleConnection
	// returns — previously it could outlive the connection for the entire
	// session TTL, accumulating leaked goroutines under high reconnect load.
	connDone := make(chan struct{})
	defer close(connDone)
	if sessionID != "" {
		go func() {
			ticker := time.NewTicker(30 * time.Second) // Update every 30 seconds
			defer ticker.Stop()
			for {
				select {
				case <-connDone:
					return
				case <-ticker.C:
					if !sm.IsSessionValid(sessionID) {
						log.Printf("🔒 Session expired for user %s, stopping updates", username)
						return
					}
					if err := sm.UpdateSessionLastSeen(sessionID); err != nil {
						log.Printf("⚠️ Failed to update session last seen: %v", err)
						return
					}
				}
			}
		}()
	}

	for newChannel := range chans {

		// Accessing username and IP address
		username := sshConn.User()
		log.Printf("📡 Starting TCP forwarding for user: %s", username)
		userIP, _, _ := net.SplitHostPort(sshConn.RemoteAddr().String())

		// AllowUdpForwarding
		if newChannel.ChannelType() == "direct-udpip" {
			go handleDirectUDPIP(newChannel, username, userIP)
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
	wg.Add(3) // Added one more goroutine for real-time traffic updates

	// Get user config for MaxTotalMB
	user, _ := users[username]
	maxTotalMB := user.MaxTotalMB

	// Get rate limiter for this user
	userLimiter := getUserRateLimiter(username)

	// Create throttled reader/writer if rate limiting is enabled
	var downloadReader io.Reader = destConn
	var downloadWriter io.Writer = channel
	var uploadReader io.Reader = channel
	var uploadWriter io.Writer = destConn

	if userLimiter != nil {
		// For download: throttle writing to channel (data from server to client)
		downloadWriter = &throttledWriter{w: channel, limiter: userLimiter, username: username}

		// For upload: throttle writing to destConn (data from client to server)
		uploadWriter = &throttledWriter{w: destConn, limiter: userLimiter, username: username}
	}

	// Optimized buffer sizes for better performance
	const bufferSize = 64 * 1024 // 64KB buffer for better throughput

	// Channel to signal when connection should be closed (limit exceeded)
	limitExceeded := make(chan bool, 1)
	var lastSent int64 = 0
	var lastReceived int64 = 0

	// Real-time traffic update goroutine.
	// Memory accounting (limit check) runs every 1s for responsiveness, but
	// disk persistence is rate-limited (every 5s) to avoid per-second JSON
	// marshalling + WriteFile, which was a major contributor to allocation
	// pressure and steady RAM growth. The 10s global flusher in startServer()
	// remains the safety net so no data is lost.
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		const saveEveryNTicks = 5
		tickCount := 0

		for {
			select {
			case <-ticker.C:
				// Get current traffic values
				currentSent := bytesSent.Load()
				currentReceived := bytesReceived.Load()

				// Calculate delta since last update
				sentDelta := currentSent - lastSent
				receivedDelta := currentReceived - lastReceived

				if sentDelta > 0 || receivedDelta > 0 {
					// Update traffic stats in real-time
					limitExceededFlag := updateTrafficStatsRealTime(username, userIP, sentDelta, receivedDelta, maxTotalMB)

					if limitExceededFlag {
						// Limit exceeded, signal to close connection
						limitExceeded <- true
						log.Printf("🚫 User %s exceeded traffic limit, closing connection", username)
						channel.Close()
						destConn.Close()
						return
					}

					tickCount++
					if tickCount >= saveEveryNTicks {
						saveTrafficStatsToFile(username)
						tickCount = 0
					}

					// Update last values
					lastSent = currentSent
					lastReceived = currentReceived
				}
			case <-limitExceeded:
				return
			}
		}
	}()

	// Receive from server → send to client (optimized with throttling)
	go func() {
		defer wg.Done()
		defer channel.CloseWrite()

		buf := make([]byte, bufferSize)
		totalBytes := int64(0)

		for {
			// Check if limit exceeded
			select {
			case <-limitExceeded:
				return
			default:
			}

			// Read with throttling
			n, err := downloadReader.Read(buf)
			if n > 0 {
				bytesReceived.Add(int64(n))
				totalBytes += int64(n)

				// Write with throttling
				if _, writeErr := downloadWriter.Write(buf[:n]); writeErr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}

		log.Printf("📥 %s received %d bytes from %s", username, totalBytes, target)
	}()

	// Send from client → to server (optimized with throttling)
	go func() {
		defer wg.Done()
		defer destConn.Close()

		buf := make([]byte, bufferSize)
		totalBytes := int64(0)

		for {
			// Check if limit exceeded
			select {
			case <-limitExceeded:
				return
			default:
			}

			// Read with throttling
			n, err := uploadReader.Read(buf)
			if n > 0 {
				bytesSent.Add(int64(n))
				totalBytes += int64(n)

				// Write with throttling
				if _, writeErr := uploadWriter.Write(buf[:n]); writeErr != nil {
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

	// Final update after connection closes
	sent := bytesSent.Load()
	received := bytesReceived.Load()

	// Update final traffic stats (in case there's any remaining delta)
	if sent > lastSent || received > lastReceived {
		sentDelta := sent - lastSent
		receivedDelta := received - lastReceived
		updateTrafficStatsRealTime(username, userIP, sentDelta, receivedDelta, maxTotalMB)
		saveTrafficStatsToFile(username)
	}

	// Update session values (for last session stats)
	statsAny, ok := trafficMap.Load(username)
	if ok {
		stats := statsAny.(*TrafficStats)
		stats.LastBytesSent = sent
		stats.LastBytesReceived = received
		stats.LastBytesTotal = sent + received
		stats.LastTimestamp = time.Now().Format(time.RFC3339)
		saveTrafficStatsToFile(username)

		log.Printf("🧠 [MEMORY] Final traffic update for %s - Session: ↑%dB ↓%dB | Total: ↑%dB ↓%dB 📦%dB",
			username, sent, received, stats.TotalBytesSent, stats.TotalBytesReceived, stats.TotalBytes)
	}
}

// UDP tunneling tuning constants. These govern the custom "direct-udpip"
// channel used by Abdal proprietary clients (this is NOT OpenSSH UDP).
const (
	// udpMaxDatagramSize is the largest single UDP payload that can be framed.
	// A 2-byte big-endian length prefix bounds this to 65535 bytes.
	udpMaxDatagramSize = 65535

	// udpSocketBufferSize enlarges the kernel UDP socket buffers so high-rate
	// flows (gaming, QUIC, media, VPN-over-UDP) do not drop packets under burst.
	udpSocketBufferSize = 4 * 1024 * 1024 // 4 MB

	// udpReadTick is how often the UDP->SSH reader wakes up to re-check the idle
	// timeout and the limit-exceeded signal while waiting for inbound datagrams.
	udpReadTick = 2 * time.Second

	// udpIdleTimeout closes a tunnel that has seen no traffic in either
	// direction for this long. UDP is connectionless, so without this an
	// abandoned flow would leak a goroutine + socket indefinitely.
	udpIdleTimeout = 90 * time.Second
)

// Handle UDP forwarding through SSH using a length-prefixed datagram framing.
//
// Wire framing on the SSH channel (both directions):
//
//	[2-byte big-endian length N][N bytes UDP payload]
//
// A frame with N == 0 is a no-op keepalive (used to keep NAT mappings and the
// idle timer fresh without forwarding an empty datagram). One channel maps to
// exactly one UDP destination, fixed at channel-open time via the standard
// direct-udpip extra-data record (host, port, originator host, originator port).
func handleDirectUDPIP(newChannel ssh.NewChannel, username string, userIP string) {
	type directUDPIPReq struct {
		HostToConnect     string
		PortToConnect     uint32
		OriginatorAddress string
		OriginatorPort    uint32
	}

	// Get user config for MaxTotalMB
	user, _ := users[username]
	maxTotalMB := user.MaxTotalMB

	// Get rate limiter for this user
	userLimiter := getUserRateLimiter(username)

	var req directUDPIPReq
	if err := ssh.Unmarshal(newChannel.ExtraData(), &req); err != nil {
		newChannel.Reject(ssh.Prohibited, "bad direct-udpip request")
		return
	}

	// Enforce per-user domain/IP block list (parity with TCP forwarding).
	if isDomainOrIPBlocked(username, req.HostToConnect) {
		log.Printf("🚫 User %s tried to access blocked UDP target: %s", username, req.HostToConnect)
		logBlockedAccess(username, req.HostToConnect, userIP)
		newChannel.Reject(ssh.Prohibited, "access to this domain/IP is blocked")
		return
	}

	// Log user access if logging is enabled for this user.
	logUserAccess(username, req.HostToConnect, userIP)

	// Resolve and dial the UDP destination.
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

	// Enlarge socket buffers for high-throughput, bursty UDP traffic.
	_ = udpConn.SetReadBuffer(udpSocketBufferSize)
	_ = udpConn.SetWriteBuffer(udpSocketBufferSize)

	channel, requests, err := newChannel.Accept()
	if err != nil {
		udpConn.Close()
		return
	}
	go ssh.DiscardRequests(requests)

	log.Printf("📡 UDP tunnel opened for %s → %s", username, addrStr)

	var bytesSent atomic.Int64
	var bytesReceived atomic.Int64
	var lastSent int64 = 0
	var lastReceived int64 = 0

	// lastActivity tracks the most recent traffic on either direction (unix
	// seconds) and drives the idle-timeout based cleanup.
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().Unix())

	// limitExceeded signals all goroutines to stop when the traffic cap is hit.
	limitExceeded := make(chan bool, 1)
	// done is closed once both transfer goroutines exit, so the stats ticker
	// stops promptly instead of leaking until an arbitrary timeout.
	done := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(2)

	// Real-time traffic accounting goroutine for UDP (same rationale as TCP):
	// in-memory limit checks every 1s, disk persistence every 5s. The global
	// 10s flusher in startServer() is the final safety net.
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		const saveEveryNTicks = 5
		tickCount := 0

		for {
			select {
			case <-ticker.C:
				currentSent := bytesSent.Load()
				currentReceived := bytesReceived.Load()

				sentDelta := currentSent - lastSent
				receivedDelta := currentReceived - lastReceived

				if sentDelta > 0 || receivedDelta > 0 {
					limitExceededFlag := updateTrafficStatsRealTime(username, userIP, sentDelta, receivedDelta, maxTotalMB)

					if limitExceededFlag {
						select {
						case limitExceeded <- true:
						default:
						}
						log.Printf("🚫 User %s exceeded traffic limit, closing UDP connection", username)
						channel.Close()
						udpConn.Close()
						return
					}

					tickCount++
					if tickCount >= saveEveryNTicks {
						saveTrafficStatsToFile(username)
						tickCount = 0
					}

					lastSent = currentSent
					lastReceived = currentReceived
				}
			case <-done:
				return
			case <-limitExceeded:
				return
			}
		}
	}()

	// SSH → UDP: read framed datagrams from the channel, write them to the
	// destination. Uses fixed reusable buffers (zero per-packet allocation).
	go func() {
		defer wg.Done()
		defer udpConn.Close()
		defer channel.CloseWrite()

		var hdr [2]byte
		payload := make([]byte, udpMaxDatagramSize)

		for {
			select {
			case <-limitExceeded:
				return
			default:
			}

			// Read the 2-byte length prefix.
			if _, err := io.ReadFull(channel, hdr[:]); err != nil {
				return
			}
			n := int(binary.BigEndian.Uint16(hdr[:]))

			// N == 0 is a keepalive: refresh activity and continue.
			if n == 0 {
				lastActivity.Store(time.Now().Unix())
				continue
			}
			if n > udpMaxDatagramSize {
				// Protocol violation; tear the tunnel down.
				return
			}

			// Read the exact payload.
			if _, err := io.ReadFull(channel, payload[:n]); err != nil {
				return
			}

			// Apply rate limiting once for the whole datagram (header + body).
			if userLimiter != nil {
				if err := userLimiter.WaitN(context.Background(), n+2); err != nil {
					return
				}
			}

			if _, err := udpConn.Write(payload[:n]); err != nil {
				return
			}

			bytesSent.Add(int64(n + 2)) // +2 accounts for the length prefix
			lastActivity.Store(time.Now().Unix())
		}
	}()

	// UDP → SSH: read datagrams from the destination, frame them, and write a
	// single combined buffer to the channel (one Write per datagram to minimize
	// SSH packet overhead). Uses one reusable frame buffer (zero per-packet alloc).
	go func() {
		defer wg.Done()
		defer channel.Close()

		// frame[0:2] holds the length prefix; frame[2:] holds the payload.
		frame := make([]byte, 2+udpMaxDatagramSize)

		for {
			select {
			case <-limitExceeded:
				return
			default:
			}

			// Wake up periodically to honor the idle timeout and stop signals.
			_ = udpConn.SetReadDeadline(time.Now().Add(udpReadTick))
			n, _, err := udpConn.ReadFromUDP(frame[2:])
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					// No data this tick; close only if fully idle.
					if time.Now().Unix()-lastActivity.Load() > int64(udpIdleTimeout.Seconds()) {
						return
					}
					continue
				}
				return
			}
			if n == 0 {
				continue
			}

			binary.BigEndian.PutUint16(frame[:2], uint16(n))

			// Apply rate limiting once for the whole datagram (header + body).
			if userLimiter != nil {
				if err := userLimiter.WaitN(context.Background(), n+2); err != nil {
					return
				}
			}

			if _, err := channel.Write(frame[:2+n]); err != nil {
				return
			}

			bytesReceived.Add(int64(n + 2)) // +2 accounts for the length prefix
			lastActivity.Store(time.Now().Unix())
		}
	}()

	// Wait for both transfer goroutines to finish, then stop the stats ticker.
	wg.Wait()
	close(done)

	log.Printf("🔌 UDP tunnel closed for %s → %s", username, addrStr)

	sent := bytesSent.Load()
	received := bytesReceived.Load()

	// Final flush of any remaining delta after the tunnel closes.
	if sent > lastSent || received > lastReceived {
		sentDelta := sent - lastSent
		receivedDelta := received - lastReceived
		updateTrafficStatsRealTime(username, userIP, sentDelta, receivedDelta, maxTotalMB)
		saveTrafficStatsToFile(username)
	}

	// Update session values (for last session stats)
	statsAny, ok := trafficMap.Load(username)
	if ok {
		stats := statsAny.(*TrafficStats)
		stats.LastBytesSent = sent
		stats.LastBytesReceived = received
		stats.LastBytesTotal = sent + received
		stats.LastTimestamp = time.Now().Format(time.RFC3339)
		saveTrafficStatsToFile(username)

		log.Printf("🧠 [MEMORY] Final UDP traffic update for %s - Session: ↑%dB ↓%dB | Total: ↑%dB ↓%dB 📦%dB",
			username, sent, received, stats.TotalBytesSent, stats.TotalBytesReceived, stats.TotalBytes)
	}
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

	// Initialize session manager and start cleanup routine
	sm := GetSessionManager()
	sm.StartCleanupRoutine()

	// Build the SSH server config exactly once. Reading + parsing the host key
	// per-connection used to be one of the biggest sources of allocation churn,
	// especially under brute-force load.
	cachedSSHConfig = createSSHConfig()

	// Start DNSTT Gateway if enabled
	if serverConfig.DNSTTEnabled {
		go startDNSTTGateway(serverConfig)
	}

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

				go handleConnection(conn, cachedSSHConfig)
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
