# Abdal 4iProto Server

<div align="center">
  <img src="src-en.jpg" alt="Abdal 4iProto Server"  >
</div>

A high-performance SSH-based tunneling server designed for secure internet access, built with advanced security features and traffic monitoring capabilities.

**📖 [فارسی](README.fa.md) | [English](README.md)**

## 📚 Documentation

Full installation, configuration, features, clients, monitoring, and guides are available here:

- 📘 **[Official Documentation](https://ebrasha.github.io/abdal-4iproto-server/)**

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
- **DNSTT Support**: Advanced DNS tunneling for secure traffic routing

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
- **Rate Limiting**: Define per-user data transfer speed limits (`max_speed_kbps`) in KB/s. Applied in real time using the Token Bucket algorithm for both upload and download.  
  **📌 Example**: `1024` = 1 MB/s

- **Traffic Limit Enforcement**: Define total traffic usage caps (`max_total_mb`) in MB. If a user exceeds the quota, access is denied at login or forcefully disconnected during active sessions.  
  **📌 Example**: `10240` = 10 GB

- **Real-time Bandwidth Enforcement**: Traffic usage is checked every 1–2 seconds. If usage exceeds the defined limit, the session is immediately terminated.

## 🚀 Easy Installation via Abdal 4iProto Cli

[**Abdal 4iProto Cli**](https://github.com/ebrasha/abdal-4iproto-cli) is an advanced CLI tool for managing the Abdal 4iProto Ecosystem. It automatically detects your OS/Architecture, verifies SHA-256 checksums, configures ports, generates SSH keys, registers persistent system services, and can install the [**Abdal 4iProto Panel**](https://github.com/ebrasha/abdal-4iproto-panel) graphical interface to manage users and full server settings.

For complete setup steps, clients, configuration, and guides, see the 📘 **[Official Documentation](https://ebrasha.github.io/abdal-4iproto-server/)**.

## 🐛 Reporting Issues
If you encounter any issues or have configuration problems, please reach out via email at Prof.Shafiei@Gmail.com. You can also report issues on GitHub.

## ❤️ Donation
If you find this project helpful and would like to support further development, please consider making a donation:
- [Donate Here](https://t.me/AbdalDonationBot)

## 🤵 Programmer
Handcrafted with Passion by **Ebrahim Shafiei (EbraSha)**
- **E-Mail**: Prof.Shafiei@Gmail.com
- **Telegram**: [@ProfShafiei](https://t.me/ProfShafiei)

## 📜 License
This project is licensed under the GPLv2 or later License.
