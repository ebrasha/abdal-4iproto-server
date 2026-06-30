/*
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal 4iProto Server
 * File Name    : config-constants.go
 * Programmer   : Ebrahim Shafiei (EbraSha)
 * Email        : Prof.Shafiei@Gmail.com
 * Created On   : 2026-06-30 04:12:29
 * Description  : Default paths, filenames, and operational constants for the server
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

package config

import "time"

// Configuration file names (relative to executable directory).
const (
	UsersFileName        = "users.json"
	ServerConfigFileName = "server_config.json"
	BlockedIPsFileName   = "blocked_ips.json"
	DefaultPrivateKey    = "id_rsa"
	DefaultPublicKey     = "id_rsa.pub"
)

// Runtime data directories (relative to executable directory).
const (
	DataDir           = "data"
	SessionsDir       = "data/sessions"
	SessionsDBFile    = "sessions.db"
	UsersTrafficDir   = "users_traffic"
	UsersLogDir       = "users_log"
	BlockedAccessDir  = "blocked_access"
	DNSTTLogDir       = "dnstt_log"
	InvalidLoginsFile = "invalid_logins.log"
	DNSTTConnections  = "dnstt_connections.log"
)

// Session defaults (overridden per-user in users.json).
const (
	DefaultMaxSessionsPerUser = 2
	DefaultSessionTTLSeconds  = 300
	BucketSessions            = "sessions"
	BucketUserSessions        = "user_sessions"
	SessionCleanupInterval    = 30 * time.Second
)

// UDP tunnel tuning defaults.
const (
	UDPMaxDatagramSize          = 65535
	UDPReadTick                 = 2 * time.Second
	DefaultUDPSocketBufferBytes = 4 * 1024 * 1024 // 4 MB
	DefaultUDPIdleTimeoutSec    = 90
)

// Traffic persistence interval for the background flusher.
const (
	TrafficAutoSaveInterval = 10 * time.Second
	DebugStatsInterval      = 30 * time.Second
)

// Windows service identifiers.
const (
	ServiceName        = "Abdal4iProtoServer"
	ServiceDisplayName = "Abdal 4iProto Server"
	ServiceDescription = "High-performance SSH-based tunneling server with advanced security features"
)
