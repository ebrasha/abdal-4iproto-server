/*
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal 4iProto Server
 * File Name    : session_manager.go
 * Author       : Ebrahim Shafiei (EbraSha)
 * Email        : Prof.Shafiei@Gmail.com
 * Created On   : 2025-10-31 01:15:00
 * Description  : Session management with BoltDB for controlling concurrent user sessions
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

package main

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

	"golang.org/x/crypto/ssh"
	"go.etcd.io/bbolt"
)

const (
	// Default maximum number of concurrent sessions per user (if not specified in users.json)
	DEFAULT_MAX_SESSIONS_PER_USER = 2

	// Default session TTL in seconds (5 minutes = 300 seconds) (if not specified in users.json)
	DEFAULT_SESSION_TTL_SECONDS = 300

	// Session database bucket names
	BUCKET_SESSIONS      = "sessions"
	BUCKET_USER_SESSIONS = "user_sessions"
)

// SessionInfo stores session information
type SessionInfo struct {
	SessionID    string    `json:"session_id"`
	Username     string    `json:"username"`
	IP           string    `json:"ip"`
	ClientVersion string    `json:"client_version"`
	CreatedAt    int64     `json:"created_at"`     // Unix timestamp in seconds
	LastSeen     int64     `json:"last_seen"`      // Unix timestamp in seconds
	Revoked      bool      `json:"revoked"`
}

// SessionManager handles session management with BoltDB
type SessionManager struct {
	db     *bbolt.DB
	mu     sync.RWMutex
	// Map to track active connections: sessionID -> ssh.Conn
	activeConnections map[string]*ssh.ServerConn
}

var sessionManager *SessionManager
var sessionManagerOnce sync.Once

// GetSessionManager returns the singleton session manager instance
func GetSessionManager() *SessionManager {
	sessionManagerOnce.Do(func() {
		exeDir, err := SetExecutableDir()
		if err != nil {
			log.Fatalf("❌ Failed to get executable directory: %v", err)
		}

		// Create data/sessions directory if it doesn't exist
		sessionsDir := filepath.Join(exeDir, "data", "sessions")
		if err := os.MkdirAll(sessionsDir, 0755); err != nil {
			log.Fatalf("❌ Failed to create sessions directory: %v", err)
		}

		dbPath := filepath.Join(sessionsDir, "sessions.db")
		db, err := bbolt.Open(dbPath, 0600, &bbolt.Options{Timeout: 1 * time.Second})
		if err != nil {
			log.Fatalf("❌ Failed to open session database: %v", err)
		}

		// Create buckets if they don't exist
		err = db.Update(func(tx *bbolt.Tx) error {
			_, err := tx.CreateBucketIfNotExists([]byte(BUCKET_SESSIONS))
			if err != nil {
				return fmt.Errorf("failed to create sessions bucket: %w", err)
			}
			_, err = tx.CreateBucketIfNotExists([]byte(BUCKET_USER_SESSIONS))
			if err != nil {
				return fmt.Errorf("failed to create user_sessions bucket: %w", err)
			}
			return nil
		})

		if err != nil {
			db.Close()
			log.Fatalf("❌ Failed to initialize session database buckets: %v", err)
		}

		sessionManager = &SessionManager{
			db:                db,
			activeConnections: make(map[string]*ssh.ServerConn),
		}

		log.Printf("✅ Session manager initialized - Database: %s", dbPath)
	})

	return sessionManager
}

// generateSessionID creates a unique session ID based on username, IP, client version, and timestamp
func generateSessionID(username, ip, clientVersion string) string {
	timestamp := time.Now().UnixNano()
	data := fmt.Sprintf("%s|%s|%s|%d", username, ip, clientVersion, timestamp)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// getUserMaxSessions returns the max sessions for a user (default if not specified)
func getUserMaxSessions(username string) int {
	if user, ok := users[username]; ok {
		if user.MaxSessions > 0 {
			return user.MaxSessions
		}
	}
	return DEFAULT_MAX_SESSIONS_PER_USER
}

// getUserSessionTTL returns the session TTL for a user (default if not specified)
func getUserSessionTTL(username string) int {
	if user, ok := users[username]; ok {
		if user.SessionTTLSeconds > 0 {
			return user.SessionTTLSeconds
		}
	}
	return DEFAULT_SESSION_TTL_SECONDS
}

// CreateSession creates a new session and closes oldest session if limit exceeded
func (sm *SessionManager) CreateSession(username, ip, clientVersion string) (string, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sessionID := generateSessionID(username, ip, clientVersion)
	now := time.Now().Unix()

	// Get user-specific max sessions
	maxSessions := getUserMaxSessions(username)

	// Get active sessions for this user
	activeSessions, err := sm.getActiveSessionsForUserLocked(username)
	if err != nil {
		return "", fmt.Errorf("failed to get active sessions: %w", err)
	}

	// If user has reached max sessions, revoke oldest session
	if len(activeSessions) >= maxSessions {
		oldestSession := sm.findOldestSession(activeSessions)
		if oldestSession != nil {
			log.Printf("🔒 Max sessions reached for %s (%d/%d), revoking oldest session: %s", username, len(activeSessions), maxSessions, oldestSession.SessionID[:16]+"...")
			sm.revokeSessionLocked(oldestSession.SessionID)
			
			// Close the connection if it exists
			if conn, exists := sm.activeConnections[oldestSession.SessionID]; exists {
				go func() {
					conn.Close()
					log.Printf("🔌 Closed connection for revoked session: %s", oldestSession.SessionID[:16]+"...")
				}()
				delete(sm.activeConnections, oldestSession.SessionID)
			}
		}
	}

	// Create new session
	session := SessionInfo{
		SessionID:    sessionID,
		Username:     username,
		IP:           ip,
		ClientVersion: clientVersion,
		CreatedAt:    now,
		LastSeen:     now,
		Revoked:      false,
	}

	// Save session to database
	err = sm.db.Update(func(tx *bbolt.Tx) error {
		sessionsBucket := tx.Bucket([]byte(BUCKET_SESSIONS))
		userSessionsBucket := tx.Bucket([]byte(BUCKET_USER_SESSIONS))

		// Serialize session
		sessionData, err := json.Marshal(session)
		if err != nil {
			return fmt.Errorf("failed to marshal session: %w", err)
		}

		// Store session
		if err := sessionsBucket.Put([]byte(sessionID), sessionData); err != nil {
			return fmt.Errorf("failed to store session: %w", err)
		}

		// Add to user's session list (key: username|lastSeen|sessionID for sorting)
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

// RegisterConnection associates a session ID with an SSH connection
func (sm *SessionManager) RegisterConnection(sessionID string, conn *ssh.ServerConn) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.activeConnections[sessionID] = conn
}

// UnregisterConnection removes a session ID from active connections
func (sm *SessionManager) UnregisterConnection(sessionID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.activeConnections, sessionID)
}

// IsSessionValid checks if a session is valid (exists, not revoked, not expired)
func (sm *SessionManager) IsSessionValid(sessionID string) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var session SessionInfo
	err := sm.db.View(func(tx *bbolt.Tx) error {
		sessionsBucket := tx.Bucket([]byte(BUCKET_SESSIONS))
		sessionData := sessionsBucket.Get([]byte(sessionID))
		if sessionData == nil {
			return fmt.Errorf("session not found")
		}
		return json.Unmarshal(sessionData, &session)
	})

	if err != nil {
		return false
	}

	// Check if session is revoked
	if session.Revoked {
		return false
	}

	// Get user-specific session TTL
	sessionTTL := getUserSessionTTL(session.Username)

	// Check if session is expired (TTL exceeded)
	now := time.Now().Unix()
	if now-session.LastSeen > int64(sessionTTL) {
		return false
	}

	return true
}

// UpdateSessionLastSeen updates the last seen timestamp for a session
func (sm *SessionManager) UpdateSessionLastSeen(sessionID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	var session SessionInfo
	err := sm.db.View(func(tx *bbolt.Tx) error {
		sessionsBucket := tx.Bucket([]byte(BUCKET_SESSIONS))
		sessionData := sessionsBucket.Get([]byte(sessionID))
		if sessionData == nil {
			return fmt.Errorf("session not found")
		}
		return json.Unmarshal(sessionData, &session)
	})

	if err != nil {
		return err
	}

	now := time.Now().Unix()
	session.LastSeen = now

	return sm.db.Update(func(tx *bbolt.Tx) error {
		sessionsBucket := tx.Bucket([]byte(BUCKET_SESSIONS))
		sessionData, err := json.Marshal(session)
		if err != nil {
			return err
		}
		return sessionsBucket.Put([]byte(sessionID), sessionData)
	})
}

// UpdateSessionClientVersion updates the client version for a session
func (sm *SessionManager) UpdateSessionClientVersion(sessionID string, clientVersion string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	var session SessionInfo
	err := sm.db.View(func(tx *bbolt.Tx) error {
		sessionsBucket := tx.Bucket([]byte(BUCKET_SESSIONS))
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
		sessionsBucket := tx.Bucket([]byte(BUCKET_SESSIONS))
		sessionData, err := json.Marshal(session)
		if err != nil {
			return err
		}
		return sessionsBucket.Put([]byte(sessionID), sessionData)
	})
}

// getActiveSessionsForUserLocked gets all active sessions for a user (must be called with lock held)
func (sm *SessionManager) getActiveSessionsForUserLocked(username string) ([]*SessionInfo, error) {
	var sessions []*SessionInfo

	err := sm.db.View(func(tx *bbolt.Tx) error {
		userSessionsBucket := tx.Bucket([]byte(BUCKET_USER_SESSIONS))
		sessionsBucket := tx.Bucket([]byte(BUCKET_SESSIONS))

		c := userSessionsBucket.Cursor()
		prefix := []byte(username + "|")

		for k, v := c.Seek(prefix); k != nil && len(k) > 0; k, v = c.Next() {
			// Check if key starts with prefix
			if len(k) < len(prefix) {
				break
			}
			if string(k[:len(prefix)]) != string(prefix) {
				break
			}

			sessionID := string(v)
			sessionData := sessionsBucket.Get([]byte(sessionID))
			if sessionData == nil {
				continue
			}

			var session SessionInfo
			if err := json.Unmarshal(sessionData, &session); err != nil {
				continue
			}

			// Only include non-revoked and non-expired sessions
			if !session.Revoked {
				// Get user-specific session TTL
				sessionTTL := getUserSessionTTL(session.Username)
				now := time.Now().Unix()
				if now-session.LastSeen <= int64(sessionTTL) {
					sessions = append(sessions, &session)
				}
			}
		}

		return nil
	})

	return sessions, err
}

// findOldestSession finds the session with the oldest LastSeen timestamp
func (sm *SessionManager) findOldestSession(sessions []*SessionInfo) *SessionInfo {
	if len(sessions) == 0 {
		return nil
	}

	oldest := sessions[0]
	for _, session := range sessions[1:] {
		if session.LastSeen < oldest.LastSeen {
			oldest = session
		}
	}

	return oldest
}

// revokeSessionLocked revokes a session (must be called with lock held)
func (sm *SessionManager) revokeSessionLocked(sessionID string) error {
	var session SessionInfo
	err := sm.db.View(func(tx *bbolt.Tx) error {
		sessionsBucket := tx.Bucket([]byte(BUCKET_SESSIONS))
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
		sessionsBucket := tx.Bucket([]byte(BUCKET_SESSIONS))
		sessionData, err := json.Marshal(session)
		if err != nil {
			return err
		}
		return sessionsBucket.Put([]byte(sessionID), sessionData)
	})
}

// CloseSession closes and removes a session
func (sm *SessionManager) CloseSession(sessionID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Close connection if exists
	if conn, exists := sm.activeConnections[sessionID]; exists {
		conn.Close()
		delete(sm.activeConnections, sessionID)
	}

	// Revoke session
	return sm.revokeSessionLocked(sessionID)
}

// CleanupExpiredSessions removes expired sessions from database
func (sm *SessionManager) CleanupExpiredSessions() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now().Unix()
	var expiredSessions []string

	err := sm.db.View(func(tx *bbolt.Tx) error {
		sessionsBucket := tx.Bucket([]byte(BUCKET_SESSIONS))

		// Find expired sessions
		return sessionsBucket.ForEach(func(k, v []byte) error {
			var session SessionInfo
			if err := json.Unmarshal(v, &session); err != nil {
				return nil // Skip invalid sessions
			}

			// Check if expired (using user-specific TTL)
			if !session.Revoked {
				sessionTTL := getUserSessionTTL(session.Username)
				if now-session.LastSeen > int64(sessionTTL) {
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

	// Remove expired sessions
	if len(expiredSessions) > 0 {
		err = sm.db.Update(func(tx *bbolt.Tx) error {
			sessionsBucket := tx.Bucket([]byte(BUCKET_SESSIONS))
			userSessionsBucket := tx.Bucket([]byte(BUCKET_USER_SESSIONS))

			for _, sessionID := range expiredSessions {
				// Get session info for username
				sessionData := sessionsBucket.Get([]byte(sessionID))
				if sessionData != nil {
					var session SessionInfo
					if json.Unmarshal(sessionData, &session) == nil {
						// Remove from user sessions bucket
						c := userSessionsBucket.Cursor()
						prefix := []byte(session.Username + "|")

						for k, v := c.Seek(prefix); k != nil && len(k) > 0; k, v = c.Next() {
							// Check if key starts with prefix
							if len(k) < len(prefix) {
								break
							}
							if string(k[:len(prefix)]) != string(prefix) {
								break
							}

							if string(v) == sessionID {
								userSessionsBucket.Delete(k)
								break
							}
						}
					}
				}

				// Remove from sessions bucket
				sessionsBucket.Delete([]byte(sessionID))

				// Close connection if exists
				if conn, exists := sm.activeConnections[sessionID]; exists {
					go conn.Close()
					delete(sm.activeConnections, sessionID)
				}
			}

			return nil
		})

		if err != nil {
			log.Printf("⚠️ Failed to remove expired sessions: %v", err)
		} else if len(expiredSessions) > 0 {
			log.Printf("🧹 Cleaned up %d expired sessions", len(expiredSessions))
		}
	}
}

// StartCleanupRoutine starts a background goroutine to cleanup expired sessions
func (sm *SessionManager) StartCleanupRoutine() {
	go func() {
		ticker := time.NewTicker(30 * time.Second) // Cleanup every 30 seconds
		defer ticker.Stop()

		for range ticker.C {
			sm.CleanupExpiredSessions()
		}
	}()

	log.Printf("✅ Session cleanup routine started (every 30 seconds)")
}

// Close closes the session manager and database
func (sm *SessionManager) Close() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Close all active connections
	for sessionID, conn := range sm.activeConnections {
		conn.Close()
		delete(sm.activeConnections, sessionID)
	}

	return sm.db.Close()
}

