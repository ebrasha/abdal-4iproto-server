/*
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal 4iProto Server
 * File Name    : blocked_ips.go
 * Programmer   : Ebrahim Shafiei (EbraSha)
 * Email        : Prof.Shafiei@Gmail.com
 * Created On   : 2026-06-30 04:12:29
 * Description  : Global IP block list and brute-force attempt tracking
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

package security

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"

	"Abdal_4iProto_Server/core/config"
	"Abdal_4iProto_Server/core/paths"
)

// Guard manages the global IP block list and failed auth counters.
type Guard struct {
	blocked    config.BlockedIPs
	blockedSet map[string]struct{}
	mu         sync.RWMutex

	failedAttempts map[string]int
	failedMu       sync.Mutex
}

// NewGuard creates an empty Guard instance.
func NewGuard() *Guard {
	return &Guard{
		blockedSet:     make(map[string]struct{}),
		failedAttempts: make(map[string]int),
	}
}

// LoadBlockedIPs reads blocked_ips.json from the executable directory.
func (g *Guard) LoadBlockedIPs() {
	exeDir, err := paths.ExecutableDir()
	if err != nil {
		log.Printf("Failed to get executable directory: %v", err)
		g.mu.Lock()
		g.blocked = config.BlockedIPs{}
		g.blockedSet = make(map[string]struct{})
		g.mu.Unlock()
		return
	}

	fullPath := filepath.Join(exeDir, config.BlockedIPsFileName)
	data, err := os.ReadFile(fullPath)

	g.mu.Lock()
	defer g.mu.Unlock()

	if err != nil {
		g.blocked = config.BlockedIPs{}
		g.blockedSet = make(map[string]struct{})
		return
	}

	_ = json.Unmarshal(data, &g.blocked)

	newSet := make(map[string]struct{}, len(g.blocked.Blocked))
	uniq := g.blocked.Blocked[:0]
	for _, ip := range g.blocked.Blocked {
		if _, ok := newSet[ip]; ok {
			continue
		}
		newSet[ip] = struct{}{}
		uniq = append(uniq, ip)
	}
	g.blocked.Blocked = uniq
	g.blockedSet = newSet
}

func (g *Guard) saveBlockedIPs() {
	exeDir, err := paths.ExecutableDir()
	if err != nil {
		log.Printf("Failed to get executable directory: %v", err)
		return
	}

	g.mu.RLock()
	data, _ := json.MarshalIndent(g.blocked, "", "  ")
	g.mu.RUnlock()

	fullPath := filepath.Join(exeDir, config.BlockedIPsFileName)
	_ = os.WriteFile(fullPath, data, 0644)
}

// IsBlocked performs an O(1) thread-safe lookup against the in-memory set.
func (g *Guard) IsBlocked(ip string) bool {
	g.mu.RLock()
	_, ok := g.blockedSet[ip]
	g.mu.RUnlock()
	return ok
}

// AddBlockedIP adds an IP to the block list (deduplicated) and persists asynchronously.
func (g *Guard) AddBlockedIP(ip string) bool {
	g.mu.Lock()
	if _, ok := g.blockedSet[ip]; ok {
		g.mu.Unlock()
		return false
	}
	g.blockedSet[ip] = struct{}{}
	g.blocked.Blocked = append(g.blocked.Blocked, ip)
	g.mu.Unlock()

	go g.saveBlockedIPs()
	return true
}

// RecordFailedLogin increments the failed attempt counter for an IP.
// Returns the new count and whether the IP should be blocked.
func (g *Guard) RecordFailedLogin(ip string) (attempts int, shouldBlock bool) {
	maxAttempts := config.MaxAuthAttempts()

	g.failedMu.Lock()
	g.failedAttempts[ip]++
	attempts = g.failedAttempts[ip]
	shouldBlock = attempts >= maxAttempts
	if shouldBlock {
		delete(g.failedAttempts, ip)
	}
	g.failedMu.Unlock()
	return attempts, shouldBlock
}

// ClearFailedAttempts resets the counter for a successful login from an IP.
func (g *Guard) ClearFailedAttempts(ip string) {
	g.failedMu.Lock()
	delete(g.failedAttempts, ip)
	g.failedMu.Unlock()
}
