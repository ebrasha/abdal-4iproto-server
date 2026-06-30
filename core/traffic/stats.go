/*
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal 4iProto Server
 * File Name    : stats.go
 * Programmer   : Ebrahim Shafiei (EbraSha)
 * Email        : Prof.Shafiei@Gmail.com
 * Created On   : 2026-06-30 04:12:29
 * Description  : Per-user traffic statistics, limits, and persistence
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

package traffic

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"Abdal_4iProto_Server/core/config"
	"Abdal_4iProto_Server/core/paths"
)

// statsMutex wraps TrafficStats with a write lock for concurrent updates.
type statsMutex struct {
	Stats *config.TrafficStats
	mu    sync.RWMutex
}

// Store tracks per-user traffic counters, rate limiters, and active connections.
type Store struct {
	trafficMap        sync.Map
	trafficStatsMutex sync.Map
	activeConnections sync.Map
	rateLimiters      sync.Map
}

// NewStore creates a traffic store.
func NewStore() *Store {
	return &Store{}
}

// MapSize returns the number of entries in the traffic map.
func (s *Store) MapSize() int {
	count := 0
	s.trafficMap.Range(func(_, _ any) bool {
		count++
		return true
	})
	return count
}

// ActiveConnectionsCount returns the number of tracked active connections.
func (s *Store) ActiveConnectionsCount() int {
	count := 0
	s.activeConnections.Range(func(_, _ any) bool {
		count++
		return true
	})
	return count
}

// StoreActiveConnection registers an active connection ID.
func (s *Store) StoreActiveConnection(connID, addr string) {
	s.activeConnections.Store(connID, addr)
}

// DeleteActiveConnection removes a connection ID from tracking.
func (s *Store) DeleteActiveConnection(connID string) {
	s.activeConnections.Delete(connID)
}

// CheckUserTrafficLimit returns an error if the user exceeded their traffic cap.
func (s *Store) CheckUserTrafficLimit(username string, maxTotalMB int) error {
	if maxTotalMB <= 0 {
		return nil
	}

	statsAny, ok := s.trafficMap.Load(username)
	if !ok {
		fullPath, err := config.TrafficFilePath(username)
		if err == nil {
			if _, err := os.Stat(fullPath); err == nil {
				data, err := os.ReadFile(fullPath)
				if err == nil {
					var fileStats config.TrafficStats
					if json.Unmarshal(data, &fileStats) == nil {
						s.trafficMap.Store(username, &fileStats)
						statsAny = &fileStats
						ok = true
					}
				}
			}
		}
		if !ok {
			return nil
		}
	}

	stats := statsAny.(*config.TrafficStats)
	maxTotalBytes := int64(maxTotalMB) * 1024 * 1024
	if stats.TotalBytes >= maxTotalBytes {
		log.Printf("🚫 User %s exceeded traffic limit: %d bytes (limit: %d MB = %d bytes)",
			username, stats.TotalBytes, maxTotalMB, maxTotalBytes)
		return fmt.Errorf("traffic limit exceeded: you have used %d MB (limit: %d MB). please contact administrator",
			stats.TotalBytes/(1024*1024), maxTotalMB)
	}
	return nil
}

// UpdateRealTime updates traffic stats in memory and returns true if limit exceeded.
func (s *Store) UpdateRealTime(username, userIP string, sent, received int64, maxTotalMB int) bool {
	statsMutexAny, ok := s.trafficStatsMutex.Load(username)
	if !ok {
		var existingStats *config.TrafficStats
		fullPath, err := config.TrafficFilePath(username)
		if err == nil {
			if data, err := os.ReadFile(fullPath); err == nil {
				var stats config.TrafficStats
				if json.Unmarshal(data, &stats) == nil {
					existingStats = &stats
				}
			}
		}
		if existingStats == nil {
			existingStats = &config.TrafficStats{
				Username: username,
				IP:       userIP,
			}
		}
		statsMutexAny = &statsMutex{Stats: existingStats}
		s.trafficStatsMutex.Store(username, statsMutexAny)
		s.trafficMap.Store(username, existingStats)
	}

	sm := statsMutexAny.(*statsMutex)
	sm.mu.Lock()
	defer sm.mu.Unlock()

	stats := sm.Stats
	stats.TotalBytesSent += sent
	stats.TotalBytesReceived += received
	stats.TotalBytes = stats.TotalBytesSent + stats.TotalBytesReceived
	stats.LastTimestamp = time.Now().Format(time.RFC3339)
	s.trafficMap.Store(username, stats)

	if maxTotalMB > 0 {
		maxTotalBytes := int64(maxTotalMB) * 1024 * 1024
		if stats.TotalBytes >= maxTotalBytes {
			log.Printf("🚫 User %s exceeded traffic limit: %d bytes (limit: %d MB = %d bytes)",
				username, stats.TotalBytes, maxTotalMB, maxTotalBytes)
			return true
		}
	}
	return false
}

// SaveToFile persists traffic stats for a user to disk.
func (s *Store) SaveToFile(username string) {
	statsAny, ok := s.trafficMap.Load(username)
	if !ok {
		return
	}
	stats := statsAny.(*config.TrafficStats)

	exeDir, err := paths.ExecutableDir()
	if err != nil {
		log.Printf("⚠️ Failed to get executable directory for saving traffic: %v", err)
		return
	}

	trafficDir := filepath.Join(exeDir, config.UsersTrafficDir)
	if err := os.MkdirAll(trafficDir, 0755); err != nil {
		log.Printf("⚠️ Failed to create users_traffic directory: %v", err)
		return
	}

	filename := fmt.Sprintf("traffic_%s.json", username)
	fullPath := filepath.Join(trafficDir, filename)
	data, err := json.MarshalIndent(stats, "", "  ")
	if err != nil {
		log.Printf("⚠️ Failed to marshal traffic stats for %s: %v", username, err)
		return
	}
	if err := os.WriteFile(fullPath, data, 0644); err != nil {
		log.Printf("⚠️ Failed to write traffic file for %s: %v", username, err)
	}
}

// LoadExistingFiles loads all traffic_*.json files from users_traffic on startup.
func (s *Store) LoadExistingFiles() {
	exeDir, err := paths.ExecutableDir()
	if err != nil {
		log.Printf("❌ Failed to get executable directory: %v", err)
		return
	}

	trafficDir := filepath.Join(exeDir, config.UsersTrafficDir)
	if err := os.MkdirAll(trafficDir, 0755); err != nil {
		log.Printf("❌ Failed to create users_traffic directory: %v", err)
		return
	}

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
		filename := file.Name()
		if len(filename) > 13 && filename[:8] == "traffic_" && filename[len(filename)-5:] == ".json" {
			username := filename[8 : len(filename)-5]
			fullPath := filepath.Join(trafficDir, filename)
			data, err := os.ReadFile(fullPath)
			if err != nil {
				log.Printf("❌ Failed to read traffic file %s: %v", filename, err)
				continue
			}
			var stats config.TrafficStats
			if err := json.Unmarshal(data, &stats); err != nil {
				log.Printf("❌ Failed to parse traffic file %s: %v", filename, err)
				continue
			}
			s.trafficMap.Store(username, &stats)
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

// UpdateSessionFinalStats updates last-session counters after a tunnel closes.
func (s *Store) UpdateSessionFinalStats(username string, sent, received int64) {
	statsAny, ok := s.trafficMap.Load(username)
	if !ok {
		return
	}
	stats := statsAny.(*config.TrafficStats)
	stats.LastBytesSent = sent
	stats.LastBytesReceived = received
	stats.LastBytesTotal = sent + received
	stats.LastTimestamp = time.Now().Format(time.RFC3339)
	s.SaveToFile(username)
	log.Printf("🧠 [MEMORY] Final traffic update for %s - Session: ↑%dB ↓%dB | Total: ↑%dB ↓%dB 📦%dB",
		username, sent, received, stats.TotalBytesSent, stats.TotalBytesReceived, stats.TotalBytes)
}

// StartAutoSave runs a background goroutine that periodically flushes all traffic stats.
func (s *Store) StartAutoSave() {
	go func() {
		exeDir, err := paths.ExecutableDir()
		if err != nil {
			log.Printf("❌ Failed to get executable directory: %v", err)
			return
		}
		trafficDir := filepath.Join(exeDir, config.UsersTrafficDir)
		if err := os.MkdirAll(trafficDir, 0755); err != nil {
			log.Printf("❌ Failed to create users_traffic directory: %v", err)
		}

		for {
			time.Sleep(config.TrafficAutoSaveInterval)
			s.trafficMap.Range(func(key, value any) bool {
				username := key.(string)
				stats := value.(*config.TrafficStats)
				filename := fmt.Sprintf("traffic_%s.json", username)
				fullPath := filepath.Join(trafficDir, filename)
				data, err := json.MarshalIndent(stats, "", "  ")
				if err != nil {
					log.Printf("❌ Failed to marshal %s: %v", username, err)
					return true
				}
				if err := os.WriteFile(fullPath, data, 0644); err != nil {
					log.Printf("❌ Failed to write traffic file for %s: %v", username, err)
					return true
				}
				log.Printf("✅ [AUTO] Saved traffic → %s | ↑%dB ↓%dB 📦 %dB",
					filename, stats.TotalBytesSent, stats.TotalBytesReceived, stats.TotalBytes)
				return true
			})
		}
	}()
}

// StartDebugTicker logs connection and traffic map sizes periodically.
func (s *Store) StartDebugTicker() {
	go func() {
		for {
			time.Sleep(config.DebugStatsInterval)
			log.Printf("🔍 [DEBUG] Active connections: %d", s.ActiveConnectionsCount())
			log.Printf("🔍 [DEBUG] Traffic map entries: %d", s.MapSize())
		}
	}()
}
