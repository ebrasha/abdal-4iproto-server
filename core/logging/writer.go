/*
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal 4iProto Server
 * File Name    : writer.go
 * Programmer   : Ebrahim Shafiei (EbraSha)
 * Email        : Prof.Shafiei@Gmail.com
 * Created On   : 2026-06-30 04:12:29
 * Description  : File-based access, auth, and DNSTT connection logging
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

package logging

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"Abdal_4iProto_Server/core/config"
	"Abdal_4iProto_Server/core/paths"
)

// InvalidLogin appends a failed authentication attempt to invalid_logins.log.
func InvalidLogin(username, password, ip string, clientPort, serverPort int) {
	exeDir, err := paths.ExecutableDir()
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

	fullPath := filepath.Join(exeDir, config.InvalidLoginsFile)
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

// BlockedAccess writes a blocked domain/IP access attempt to the user log directory.
func BlockedAccess(username, target, userIP string) {
	exeDir, err := paths.ExecutableDir()
	if err != nil {
		log.Printf("❌ Failed to get executable directory: %v", err)
		return
	}

	blockedDir := filepath.Join(exeDir, config.BlockedAccessDir)
	if err := os.MkdirAll(blockedDir, 0755); err != nil {
		log.Printf("❌ Failed to create blocked_access directory: %v", err)
		return
	}

	logEntry := fmt.Sprintf(
		"[🚫 Blocked Access] [%s] Target: %s | User IP: %s\n",
		time.Now().Format("2006-01-02 15:04:05"),
		target,
		userIP,
	)

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

// UserAccess writes a tunnel access record when per-user logging is enabled.
func UserAccess(username, target, userIP string) {
	user, exists := config.GetUser(username)
	if !exists || user.Log != "yes" {
		return
	}

	exeDir, err := paths.ExecutableDir()
	if err != nil {
		log.Printf("❌ Failed to get executable directory: %v", err)
		return
	}

	usersLogDir := filepath.Join(exeDir, config.UsersLogDir)
	if err := os.MkdirAll(usersLogDir, 0755); err != nil {
		log.Printf("❌ Failed to create users_log directory: %v", err)
		return
	}

	logEntry := fmt.Sprintf(
		"[📡 User Access] [%s] Target: %s | User IP: %s\n",
		time.Now().Format("2006-01-02 15:04:05"),
		target,
		userIP,
	)

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

// DNSTTConnection appends a DNSTT connection record to the gateway log.
func DNSTTConnection(userIP string, sessionID uint32, serverPort int) {
	exeDir, err := paths.ExecutableDir()
	if err != nil {
		log.Printf("❌ Failed to get executable directory: %v", err)
		return
	}

	dnsttLogDir := filepath.Join(exeDir, config.DNSTTLogDir)
	if err := os.MkdirAll(dnsttLogDir, 0755); err != nil {
		log.Printf("❌ Failed to create dnstt_log directory: %v", err)
		return
	}

	logEntry := fmt.Sprintf(
		"[🔗 DNSTT Connection] [%s] IP: %s | Session: %08x | Server Port: %d\n",
		time.Now().Format("2006-01-02 15:04:05"),
		userIP,
		sessionID,
		serverPort,
	)

	fullPath := filepath.Join(dnsttLogDir, config.DNSTTConnections)
	f, err := os.OpenFile(fullPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Failed to open DNSTT log file: %v", err)
		return
	}
	defer f.Close()

	if _, err := f.WriteString(logEntry); err != nil {
		log.Printf("Failed to write DNSTT connection log: %v", err)
	}
}
