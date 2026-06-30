/*
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal 4iProto Server
 * File Name    : connection.go
 * Programmer   : Ebrahim Shafiei (EbraSha)
 * Email        : Prof.Shafiei@Gmail.com
 * Created On   : 2026-06-30 04:12:29
 * Description  : SSH connection acceptance, session validation, and channel dispatch
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

package sshserver

import (
	"fmt"
	"log"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// HandleConnection processes a new TCP connection through the SSH handshake.
func (h *Handler) HandleConnection(conn net.Conn, sshConfig *ssh.ServerConfig) {
	if remoteIP, _, splitErr := net.SplitHostPort(conn.RemoteAddr().String()); splitErr == nil {
		if h.Guard.IsBlocked(remoteIP) {
			conn.Close()
			return
		}
	}

	conn.Write([]byte("Abdal 4iProto Server\n"))

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, sshConfig)
	if err != nil {
		log.Printf("Failed to handshake: %s", err)
		return
	}
	defer sshConn.Close()

	username := sshConn.User()
	userIP, _, _ := net.SplitHostPort(sshConn.RemoteAddr().String())
	clientVersion := string(sshConn.ClientVersion())

	var sessionID string
	perms := sshConn.Permissions
	if perms != nil && perms.Extensions != nil {
		if sid, ok := perms.Extensions["session_id"]; ok {
			sessionID = sid
		}
	}

	metaKey := username + "|" + userIP
	if sessionID == "" {
		if sid, ok := sessionMetadata.Load(metaKey); ok {
			sessionID = sid.(string)
		}
	}
	sessionMetadata.Delete(metaKey)

	if sessionID != "" {
		if !h.Sessions.IsSessionValid(sessionID) {
			log.Printf("🔒 Invalid or expired session for user %s from %s, closing connection", username, userIP)
			return
		}

		h.Sessions.RegisterConnection(sessionID, sshConn)

		if err := h.Sessions.UpdateClientVersion(sessionID, clientVersion); err != nil {
			log.Printf("⚠️ Failed to update session client version: %v", err)
		}
		if err := h.Sessions.UpdateLastSeen(sessionID); err != nil {
			log.Printf("⚠️ Failed to update session last seen: %v", err)
		}

		defer func() {
			h.Sessions.UnregisterConnection(sessionID)
			h.Sessions.CloseSession(sessionID)
		}()

		log.Printf("🔐 Session validated: %s for user %s from %s", sessionID[:16]+"...", username, userIP)
	} else {
		log.Printf("⚠️ No sessionID found for user %s from %s, connection may not be tracked", username, userIP)
	}

	connID := fmt.Sprintf("%s-%d", sshConn.RemoteAddr().String(), time.Now().UnixNano())
	h.Traffic.StoreActiveConnection(connID, sshConn.RemoteAddr().String())
	defer h.Traffic.DeleteActiveConnection(connID)

	log.Printf("New SSH connection from %s (%s)", sshConn.RemoteAddr(), clientVersion)
	go ssh.DiscardRequests(reqs)

	connDone := make(chan struct{})
	defer close(connDone)
	if sessionID != "" {
		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-connDone:
					return
				case <-ticker.C:
					if !h.Sessions.IsSessionValid(sessionID) {
						log.Printf("🔒 Session expired for user %s, stopping updates", username)
						return
					}
					if err := h.Sessions.UpdateLastSeen(sessionID); err != nil {
						log.Printf("⚠️ Failed to update session last seen: %v", err)
						return
					}
				}
			}
		}()
	}

	for newChannel := range chans {
		username := sshConn.User()
		log.Printf("📡 Starting TCP forwarding for user: %s", username)
		userIP, _, _ := net.SplitHostPort(sshConn.RemoteAddr().String())

		if newChannel.ChannelType() == "direct-udpip" {
			go h.HandleDirectUDPIP(newChannel, username, userIP)
			continue
		}

		if newChannel.ChannelType() == "direct-tcpip" {
			go h.HandleDirectTCPIP(newChannel, username, userIP)
			log.Printf("⚡ Received direct-tcpip from %s", username)
			continue
		}

		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("Channel accept failed: %v", err)
			continue
		}
		go h.HandleSession(channel, requests, sshConn.User())
	}
}
