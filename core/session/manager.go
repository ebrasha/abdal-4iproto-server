/*
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal 4iProto Server
 * File Name    : manager.go
 * Programmer   : Ebrahim Shafiei (EbraSha)
 * Email        : Prof.Shafiei@Gmail.com
 * Created On   : 2026-06-30 04:12:29
 * Description  : Session management with BoltDB for controlling concurrent user sessions
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

package session

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"Abdal_4iProto_Server/core/config"
	"Abdal_4iProto_Server/core/paths"

	"go.etcd.io/bbolt"
	"golang.org/x/crypto/ssh"
)

// Info stores session metadata persisted in BoltDB.
type Info struct {
	SessionID     string `json:"session_id"`
	Username      string `json:"username"`
	IP            string `json:"ip"`
	ClientVersion string `json:"client_version"`
	CreatedAt     int64  `json:"created_at"`
	LastSeen      int64  `json:"last_seen"`
	Revoked       bool   `json:"revoked"`
}

// Manager handles session lifecycle with BoltDB persistence.
type Manager struct {
	db                *bbolt.DB
	mu                sync.RWMutex
	activeConnections map[string]*ssh.ServerConn
}

var (
	instance     *Manager
	instanceOnce sync.Once
)

// GetManager returns the singleton session manager instance.
func GetManager() *Manager {
	instanceOnce.Do(func() {
		exeDir, err := paths.ExecutableDir()
		if err != nil {
			log.Fatalf("❌ Failed to get executable directory: %v", err)
		}

		sessionsDir := filepath.Join(exeDir, config.SessionsDir)
		if err := os.MkdirAll(sessionsDir, 0755); err != nil {
			log.Fatalf("❌ Failed to create sessions directory: %v", err)
		}

		dbPath := filepath.Join(sessionsDir, config.SessionsDBFile)
		if _, err := os.Stat(dbPath); err == nil {
			if err := os.Remove(dbPath); err != nil {
				log.Printf("⚠️ Failed to remove old session database: %v", err)
			} else {
				log.Printf("🗑️ Removed old session database: %s", dbPath)
			}
		}

		db, err := bbolt.Open(dbPath, 0600, &bbolt.Options{Timeout: 1 * time.Second})
		if err != nil {
			log.Fatalf("❌ Failed to open session database: %v", err)
		}

		err = db.Update(func(tx *bbolt.Tx) error {
			if _, err := tx.CreateBucketIfNotExists([]byte(config.BucketSessions)); err != nil {
				return fmt.Errorf("failed to create sessions bucket: %w", err)
			}
			if _, err := tx.CreateBucketIfNotExists([]byte(config.BucketUserSessions)); err != nil {
				return fmt.Errorf("failed to create user_sessions bucket: %w", err)
			}
			return nil
		})
		if err != nil {
			db.Close()
			log.Fatalf("❌ Failed to initialize session database buckets: %v", err)
		}

		instance = &Manager{
			db:                db,
			activeConnections: make(map[string]*ssh.ServerConn),
		}
		log.Printf("✅ Session manager initialized - Database: %s", dbPath)
	})
	return instance
}

func generateSessionID(username, ip, clientVersion string) string {
	timestamp := time.Now().UnixNano()
	data := fmt.Sprintf("%s|%s|%s|%d", username, ip, clientVersion, timestamp)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func userMaxSessions(username string) int {
	if user, ok := config.GetUser(username); ok && user.MaxSessions > 0 {
		return user.MaxSessions
	}
	return config.DefaultMaxSessionsPerUser
}

func userSessionTTL(username string) int {
	if user, ok := config.GetUser(username); ok && user.SessionTTLSeconds > 0 {
		return user.SessionTTLSeconds
	}
	return config.DefaultSessionTTLSeconds
}

// CreateSession creates a new session and rejects if max sessions limit exceeded.
func (sm *Manager) CreateSession(username, ip, clientVersion string) (string, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sessionID := generateSessionID(username, ip, clientVersion)
	now := time.Now().Unix()
	maxSessions := userMaxSessions(username)

	activeSessions, err := sm.getActiveSessionsForUserLocked(username)
	if err != nil {
		return "", fmt.Errorf("failed to get active sessions: %w", err)
	}

	if len(activeSessions) >= maxSessions {
		log.Printf("🚫 Max sessions reached for %s (%d/%d), rejecting new connection from %s", username, len(activeSessions), maxSessions, ip)
		return "", fmt.Errorf("maximum concurrent sessions limit reached (%d/%d). please wait for an existing session to close", len(activeSessions), maxSessions)
	}

	session := Info{
		SessionID:     sessionID,
		Username:      username,
		IP:            ip,
		ClientVersion: clientVersion,
		CreatedAt:     now,
		LastSeen:      now,
		Revoked:       false,
	}

	err = sm.db.Update(func(tx *bbolt.Tx) error {
		sessionsBucket := tx.Bucket([]byte(config.BucketSessions))
		userSessionsBucket := tx.Bucket([]byte(config.BucketUserSessions))

		sessionData, err := json.Marshal(session)
		if err != nil {
			return fmt.Errorf("failed to marshal session: %w", err)
		}
		if err := sessionsBucket.Put([]byte(sessionID), sessionData); err != nil {
			return fmt.Errorf("failed to store session: %w", err)
		}

		userSessionKey := fmt.Sprintf("%s|%d|%s", username, now, sessionID)
		if err := userSessionsBucket.Put([]byte(userSessionKey), []byte(sessionID)); err != nil {
			return fmt.Errorf("failed to store user session: %w", err)
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}

	log.Printf("✅ Session created: %s for user %s from %s", sessionID[:16]+"...", username, ip)
	return sessionID, nil
}

// RegisterConnection associates a session ID with an SSH connection.
func (sm *Manager) RegisterConnection(sessionID string, conn *ssh.ServerConn) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.activeConnections[sessionID] = conn
}

// UnregisterConnection removes a session ID from active connections.
func (sm *Manager) UnregisterConnection(sessionID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.activeConnections, sessionID)
}

// IsSessionValid checks if a session exists, is not revoked, and has not expired.
func (sm *Manager) IsSessionValid(sessionID string) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var session Info
	err := sm.db.View(func(tx *bbolt.Tx) error {
		sessionsBucket := tx.Bucket([]byte(config.BucketSessions))
		sessionData := sessionsBucket.Get([]byte(sessionID))
		if sessionData == nil {
			return fmt.Errorf("session not found")
		}
		return json.Unmarshal(sessionData, &session)
	})
	if err != nil {
		return false
	}
	if session.Revoked {
		return false
	}
	now := time.Now().Unix()
	if now-session.LastSeen > int64(userSessionTTL(session.Username)) {
		return false
	}
	return true
}

// UpdateLastSeen updates the last seen timestamp for a session.
func (sm *Manager) UpdateLastSeen(sessionID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	var session Info
	err := sm.db.View(func(tx *bbolt.Tx) error {
		sessionsBucket := tx.Bucket([]byte(config.BucketSessions))
		sessionData := sessionsBucket.Get([]byte(sessionID))
		if sessionData == nil {
			return fmt.Errorf("session not found")
		}
		return json.Unmarshal(sessionData, &session)
	})
	if err != nil {
		return err
	}

	session.LastSeen = time.Now().Unix()
	return sm.db.Update(func(tx *bbolt.Tx) error {
		sessionsBucket := tx.Bucket([]byte(config.BucketSessions))
		sessionData, err := json.Marshal(session)
		if err != nil {
			return err
		}
		return sessionsBucket.Put([]byte(sessionID), sessionData)
	})
}

// UpdateClientVersion updates the client version for a session.
func (sm *Manager) UpdateClientVersion(sessionID, clientVersion string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	var session Info
	err := sm.db.View(func(tx *bbolt.Tx) error {
		sessionsBucket := tx.Bucket([]byte(config.BucketSessions))
		sessionData := sessionsBucket.Get([]byte(sessionID))
		if sessionData == nil {
			return fmt.Errorf("session not found")
		}
		return json.Unmarshal(sessionData, &session)
	})
	if err != nil {
		return err
	}

	session.ClientVersion = clientVersion
	return sm.db.Update(func(tx *bbolt.Tx) error {
		sessionsBucket := tx.Bucket([]byte(config.BucketSessions))
		sessionData, err := json.Marshal(session)
		if err != nil {
			return err
		}
		return sessionsBucket.Put([]byte(sessionID), sessionData)
	})
}

func (sm *Manager) getActiveSessionsForUserLocked(username string) ([]*Info, error) {
	var sessions []*Info
	err := sm.db.View(func(tx *bbolt.Tx) error {
		userSessionsBucket := tx.Bucket([]byte(config.BucketUserSessions))
		sessionsBucket := tx.Bucket([]byte(config.BucketSessions))
		c := userSessionsBucket.Cursor()
		prefix := []byte(username + "|")

		for k, v := c.Seek(prefix); k != nil && len(k) > 0; k, v = c.Next() {
			if len(k) < len(prefix) || string(k[:len(prefix)]) != string(prefix) {
				break
			}
			sessionID := string(v)
			sessionData := sessionsBucket.Get([]byte(sessionID))
			if sessionData == nil {
				continue
			}
			var session Info
			if err := json.Unmarshal(sessionData, &session); err != nil {
				continue
			}
			if !session.Revoked {
				ttl := userSessionTTL(session.Username)
				now := time.Now().Unix()
				if now-session.LastSeen <= int64(ttl) {
					sessions = append(sessions, &session)
				}
			}
		}
		return nil
	})
	return sessions, err
}

func (sm *Manager) revokeSessionLocked(sessionID string) error {
	var session Info
	err := sm.db.View(func(tx *bbolt.Tx) error {
		sessionsBucket := tx.Bucket([]byte(config.BucketSessions))
		sessionData := sessionsBucket.Get([]byte(sessionID))
		if sessionData == nil {
			return fmt.Errorf("session not found")
		}
		return json.Unmarshal(sessionData, &session)
	})
	if err != nil {
		return err
	}

	session.Revoked = true
	session.LastSeen = time.Now().Unix()
	return sm.db.Update(func(tx *bbolt.Tx) error {
		sessionsBucket := tx.Bucket([]byte(config.BucketSessions))
		sessionData, err := json.Marshal(session)
		if err != nil {
			return err
		}
		return sessionsBucket.Put([]byte(sessionID), sessionData)
	})
}

// CloseSession closes and revokes a session.
func (sm *Manager) CloseSession(sessionID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if conn, exists := sm.activeConnections[sessionID]; exists {
		conn.Close()
		delete(sm.activeConnections, sessionID)
	}
	return sm.revokeSessionLocked(sessionID)
}

// CleanupExpiredSessions removes expired sessions from the database.
func (sm *Manager) CleanupExpiredSessions() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now().Unix()
	var expiredSessions []string

	err := sm.db.View(func(tx *bbolt.Tx) error {
		sessionsBucket := tx.Bucket([]byte(config.BucketSessions))
		return sessionsBucket.ForEach(func(_, v []byte) error {
			var session Info
			if err := json.Unmarshal(v, &session); err != nil {
				return nil
			}
			if !session.Revoked {
				ttl := userSessionTTL(session.Username)
				if now-session.LastSeen > int64(ttl) {
					expiredSessions = append(expiredSessions, session.SessionID)
				}
			}
			return nil
		})
	})
	if err != nil {
		log.Printf("⚠️ Failed to find expired sessions: %v", err)
		return
	}

	if len(expiredSessions) > 0 {
		err = sm.db.Update(func(tx *bbolt.Tx) error {
			sessionsBucket := tx.Bucket([]byte(config.BucketSessions))
			userSessionsBucket := tx.Bucket([]byte(config.BucketUserSessions))

			for _, sessionID := range expiredSessions {
				sessionData := sessionsBucket.Get([]byte(sessionID))
				if sessionData != nil {
					var session Info
					if json.Unmarshal(sessionData, &session) == nil {
						c := userSessionsBucket.Cursor()
						prefix := []byte(session.Username + "|")
						for k, v := c.Seek(prefix); k != nil && len(k) > 0; k, v = c.Next() {
							if len(k) < len(prefix) || string(k[:len(prefix)]) != string(prefix) {
								break
							}
							if string(v) == sessionID {
								userSessionsBucket.Delete(k)
								break
							}
						}
					}
				}
				sessionsBucket.Delete([]byte(sessionID))
				if conn, exists := sm.activeConnections[sessionID]; exists {
					go conn.Close()
					delete(sm.activeConnections, sessionID)
				}
			}
			return nil
		})
		if err != nil {
			log.Printf("⚠️ Failed to remove expired sessions: %v", err)
		} else {
			log.Printf("🧹 Cleaned up %d expired sessions", len(expiredSessions))
		}
	}
}

// StartCleanupRoutine starts a background goroutine to cleanup expired sessions.
func (sm *Manager) StartCleanupRoutine() {
	go func() {
		ticker := time.NewTicker(config.SessionCleanupInterval)
		defer ticker.Stop()
		for range ticker.C {
			sm.CleanupExpiredSessions()
		}
	}()
	log.Printf("✅ Session cleanup routine started (every %v)", config.SessionCleanupInterval)
}

// Close closes the session manager and database.
func (sm *Manager) Close() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	for sessionID, conn := range sm.activeConnections {
		conn.Close()
		delete(sm.activeConnections, sessionID)
	}
	return sm.db.Close()
}
