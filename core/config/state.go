/*
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal 4iProto Server
 * File Name    : state.go
 * Programmer   : Ebrahim Shafiei (EbraSha)
 * Email        : Prof.Shafiei@Gmail.com
 * Created On   : 2026-06-30 04:12:29
 * Description  : Thread-safe accessors for loaded configuration state
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

package config

import "sync"

var (
	stateMu    sync.RWMutex
	users      map[string]User
	serverConf ServerConfig
)

// SetUsers replaces the in-memory user map after loading.
func SetUsers(u map[string]User) {
	stateMu.Lock()
	users = u
	stateMu.Unlock()
}

// SetServerConfig replaces the in-memory server configuration.
func SetServerConfig(c ServerConfig) {
	stateMu.Lock()
	serverConf = c
	stateMu.Unlock()
}

// GetUser returns a user by username.
func GetUser(username string) (User, bool) {
	stateMu.RLock()
	u, ok := users[username]
	stateMu.RUnlock()
	return u, ok
}

// Users returns a shallow copy of the user map for iteration.
func Users() map[string]User {
	stateMu.RLock()
	defer stateMu.RUnlock()
	out := make(map[string]User, len(users))
	for k, v := range users {
		out[k] = v
	}
	return out
}

// Server returns the loaded server configuration.
func Server() ServerConfig {
	stateMu.RLock()
	defer stateMu.RUnlock()
	return serverConf
}

// MaxAuthAttempts returns the configured brute-force threshold.
func MaxAuthAttempts() int {
	return Server().MaxAuthAttempts
}
