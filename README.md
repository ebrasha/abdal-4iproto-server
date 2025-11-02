# Abdal 4iProto Server

<div align="center">
  <img src="src.png" alt="Abdal 4iProto Server" width="600">
</div>

A high-performance SSH-based tunneling server designed for secure internet access, built with advanced security features and traffic monitoring capabilities.

**📖 [فارسی](README.fa.md) | [English](README.md)**

## 🚀 Features

### 🔒 Security Features
- **Built-in Brute Force Protection**: Automatic IP blocking after failed authentication attempts
- **Attack Monitoring**: Detailed logging of failed login attempts with IP tracking
- **Customizable Authentication**: Configurable maximum authentication attempts
- **IP Blocking System**: Persistent blocked IP management with JSON storage
- **Server Banner Customization**: Hide or customize server banner via configuration
- **Setting Access Levels**: Has two modes: User and Administrator. Administrators have the capability to execute commands in the operating system shell, while Users can only establish tunnels.

### 📊 Traffic Monitoring
- **Real-time Traffic Tracking**: Monitor upload/download usage per user
- **Session-based Statistics**: Track bytes sent/received per session
- **Total Usage Analytics**: Cumulative traffic statistics across all sessions
- **Automatic Data Persistence**: Traffic data saved to JSON files every 10 seconds
- **Live Bandwidth Monitoring**: Real-time bandwidth usage display
- **Blocking Unauthorized Websites**: Blocks websites that you do not want the user to visit.
- **Blocking Unauthorized IPs**: Blocks IP addresses that you do not want the user to visit.
- **Tracking Visited Websites**: The ability to track the websites visited by the user, a feature you can enable or disable

### 🌐 Network Capabilities
- **Multi-port Support**: Run server on multiple ports simultaneously
- **TCP Forwarding**: Direct TCP connection forwarding without additional configuration
- **UDP Forwarding**: Full UDP traffic forwarding support
- **Cross-platform**: Runs on both Linux and Windows systems
- **High Performance**: 10x faster than OpenSSH for tunneling operations

### 🛠️ Management Features
- **User Management**: JSON-based user authentication system
- **Shell Integration**: Native CMD support on Windows and Shell on Linux
- **Configuration Management**: JSON-based server configuration
- **Logging System**: Comprehensive logging of connections and attacks

### 🧾 Accounting Features
- **Built-in Session Control**: Administrators can define how many concurrent sessions each account can open at the same time.
- **Automatic Session Expiration**: Each session has a defined Time To Live (TTL). Expired sessions are automatically terminated to free resources.
- **Dynamic Connection Handling**: When the session limit is reached, new connections can be rejected or queued — fully configurable.
- **Real-time Session Monitoring**: Tracks and logs all active sessions in real time for auditing and analytics.
- **Immediate blocking of new connections when sessions are saturated**: If an account exceeds the allowed session limit, any new users attempting to connect will be blocked from the very beginning and denied access.


## 📋 Requirements

- Go 1.19 or higher
- SSH private key (`id_rsa`)
- Configuration files (see Setup section)

## ⚙️ Setup

### 1. Configuration Files

#### `server_config.json`
#### Windows

```json


{
  "ports": [64235, 64236,64237],
  "shell": "cmd.exe",
  "max_auth_attempts": 3,
  "server_version": "SSH-2.0-Abdal-4iProto-Server"
}
```
#### linux 

```json
{
  "ports": [64235, 64236,64237],
  "shell": "/bin/bash",
  "max_auth_attempts": 3,
  "server_version": "SSH-2.0-Abdal-4iProto-Server"
}
```




#### `users.json`

```json

[
  {
    "username": "ebrasha",
    "password": "152314562152",
    "role": "admin",
    "blocked_domains": [],
    "blocked_ips": [],
    "log": "no",
    "max_sessions": 1,
    "session_ttl_seconds": 300
  },
  {
    "username": "user1",
    "password": "password123",
    "role": "user",
    "blocked_domains": [
      "facebook.com",
      "*.facebook.com",
      "twitter.com",
      "*.twitter.com",
      "instagram.com",
      "*.instagram.com"
    ],
    "blocked_ips": [
      "192.168.1.100",
      "10.0.0.*",
      "172.16.*.*"
    ],
    "log": "yes",
    "max_sessions": 2,
    "session_ttl_seconds": 300
  },
  {
    "username": "user2",
    "password": "password456",
    "role": "user",
    "blocked_domains": [
      "youtube.com",
      "*.youtube.com",
      "netflix.com",
      "*.netflix.com"
    ],
    "blocked_ips": [
      "192.168.10.1",
      "10.10.10.10"
    ],
    "log": "yes",
    "max_sessions": 5,
    "session_ttl_seconds": 300
  }
]

```

#### `blocked_ips.json`

```json
{
  "blocked": [
    "192.168.1.12",
    "10.0.0.7"
  ]
}
```

### 2. SSH Key Setup
Place your SSH private key as `id_rsa` in the project directory.

Run the following command in the server's file directory to generate a new key.

```bash
ssh-keygen -t rsa -b 4096 -f id_rsa
```

### 3. Build and Run
```bash
go mod tidy
go build -o abdal-4iproto-server
./abdal-4iproto-server
```



## 🔧 Configuration Options

### Server Configuration (`server_config.json`)
- `ports`: Array of ports to listen on
- `shell`: Shell command to execute (cmd.exe for Windows, /bin/bash for Linux)
- `max_auth_attempts`: Maximum failed login attempts before IP blocking
- `server_version`: Custom SSH server version string

### Traffic Monitoring
The server automatically tracks:
- Bytes sent/received per session
- Total traffic per user
- Session timestamps
- Real-time bandwidth usage

## 🚀 Usage
 

### Starting the Server
```bash
./abdal-4iproto-server
```

### Connecting via Custom Client
We have developed a dedicated client with GUI support that also supports SOCKS5 server creation. For the best experience, use our custom client:

**Download Client**: [Abdal 4iProto Client](https://github.com/ebrasha/abdal-4iproto-client)

### Alternative: Standard SSH Connection
```bash
ssh -D 1080 username@server_ip -p 22
```

### SOCKS Proxy Usage
After establishing connection with dynamic forwarding:
- Configure applications to use SOCKS proxy on localhost:52905
- All traffic will be tunneled through the secure SSH connection

## 🚀 4iProto Client Options

You can connect to the **Abdal 4iProto Server** from all major platforms using the following clients:

### 🐧 Linux Client

Use [`sshuttle`](https://github.com/sshuttle/sshuttle) for full-tunnel routing via SSH:

```bash
sshuttle --dns -r ebrasha@91.107.170.50:2222 0.0.0.0/0 -vv
```

### 🪟 Windows Client

[Download Abdal 4iProto Client for Windows](https://github.com/ebrasha/abdal-4iproto-client)

### 🤖 Android Client

[Download NapsternetV from Google Play](https://play.google.com/store/apps/details?id=com.napsternetlabs.napsternetv&hl=en)

### 🍏 iPhone (iOS) Client

[Download SSH Tunnel with SOCKS5 Proxy from App Store](https://apps.apple.com/de/app/ssh-tunnel-with-socks5-proxy/id1260223542)


## 📊 Monitoring

### Traffic Statistics
Traffic data is automatically saved to `traffic_username.json` files:
```json
{
  "username": "user1",
  "ip": "192.168.1.100",
  "last_bytes_sent": 1024,
  "last_bytes_received": 2048,
  "total_bytes_sent": 1048576,
  "total_bytes_received": 2097152,
  "total_bytes": 3145728,
  "last_timestamp": "2025-01-15T10:30:00Z"
}
```

### Log Files
- `invalid_logins.log`: Records failed authentication attempts
- `blocked_ips.json`: Manages blocked IP addresses
- Console output: Real-time connection and traffic logs

## 🔒 Security Features

### Brute Force Protection
- Automatic IP blocking after configurable failed attempts
- Persistent blocked IP storage
- Detailed attack logging with timestamps

### Attack Monitoring
- Logs failed login attempts with username, password, and IP
- Tracks attack patterns and sources
- Provides comprehensive security analytics

## 🐛 Reporting Issues
If you encounter any issues or have configuration problems, please reach out via email at Prof.Shafiei@Gmail.com. You can also report issues on GitLab or GitHub.

## ❤️ Donation
If you find this project helpful and would like to support further development, please consider making a donation:
- [Donate Here](https://ebrasha.com/abdal-donation)

## 🤵 Programmer
Handcrafted with Passion by **Ebrahim Shafiei (EbraSha)**
- **E-Mail**: Prof.Shafiei@Gmail.com
- **Telegram**: [@ProfShafiei](https://t.me/ProfShafiei)

## 📜 License
This project is licensed under the GPLv2 or later License. 