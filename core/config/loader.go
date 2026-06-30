/*
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal 4iProto Server
 * File Name    : loader.go
 * Programmer   : Ebrahim Shafiei (EbraSha)
 * Email        : Prof.Shafiei@Gmail.com
 * Created On   : 2026-06-30 04:12:29
 * Description  : Loads users and server configuration from JSON files
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

package config

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"Abdal_4iProto_Server/core/paths"
)

// RateLimiterInit is called for each user with a speed cap after users are loaded.
type RateLimiterInit func(username string, maxSpeedKBPS int)

// LoadUsers reads and parses users.json from the executable directory.
func LoadUsers(rateInit RateLimiterInit) {
	exeDir, err := paths.ExecutableDir()
	if err != nil {
		log.Fatalf("Failed to get executable directory: %v", err)
	}

	fullPath := filepath.Join(exeDir, UsersFileName)
	data, err := os.ReadFile(fullPath)
	if err != nil {
		log.Fatalf("Failed to read users file: %v", err)
	}

	var userList []User
	if err := json.Unmarshal(data, &userList); err == nil {
		u := make(map[string]User)
		for _, user := range userList {
			if user.MaxSessions <= 0 {
				user.MaxSessions = DefaultMaxSessionsPerUser
			}
			if user.SessionTTLSeconds <= 0 {
				user.SessionTTLSeconds = DefaultSessionTTLSeconds
			}
			if user.MaxTotalMB < 0 {
				user.MaxTotalMB = 0
			}
			u[user.Username] = user
			if rateInit != nil && user.MaxSpeedKBPS > 0 {
				rateInit(user.Username, user.MaxSpeedKBPS)
			}
		}
		SetUsers(u)
		log.Printf("✅ Loaded %d users with role-based access control", len(u))
		return
	}

	var oldUserPass map[string]string
	if err := json.Unmarshal(data, &oldUserPass); err != nil {
		log.Fatalf("Failed to parse users file: %v", err)
	}

	u := make(map[string]User)
	for username, password := range oldUserPass {
		u[username] = User{
			Username:          username,
			Password:          password,
			Role:              "user",
			MaxSessions:       DefaultMaxSessionsPerUser,
			SessionTTLSeconds: DefaultSessionTTLSeconds,
			MaxTotalMB:        0,
		}
	}
	SetUsers(u)
	log.Printf("✅ Loaded %d users from legacy format (all set to 'user' role)", len(u))
}

// LoadServerConfig reads and parses server_config.json from the executable directory.
func LoadServerConfig() {
	exeDir, err := paths.ExecutableDir()
	if err != nil {
		log.Fatalf("Failed to get executable directory: %v", err)
	}

	fullPath := filepath.Join(exeDir, ServerConfigFileName)
	data, err := os.ReadFile(fullPath)
	if err != nil {
		log.Fatalf("Failed to read server config file: %v", err)
	}

	var cfg ServerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("Failed to parse server config file: %v", err)
	}
	SetServerConfig(cfg)
}

// PrivateKeyPath resolves the host private key path relative to the executable directory.
func PrivateKeyPath() (string, error) {
	exeDir, err := paths.ExecutableDir()
	if err != nil {
		return "", err
	}
	keyFile := Server().PrivateKeyFile
	if keyFile == "" {
		keyFile = DefaultPrivateKey
	}
	return filepath.Join(exeDir, keyFile), nil
}

// TrafficFilePath returns the per-user traffic stats file path.
func TrafficFilePath(username string) (string, error) {
	exeDir, err := paths.ExecutableDir()
	if err != nil {
		return "", err
	}
	filename := fmt.Sprintf("traffic_%s.json", username)
	return filepath.Join(exeDir, UsersTrafficDir, filename), nil
}
