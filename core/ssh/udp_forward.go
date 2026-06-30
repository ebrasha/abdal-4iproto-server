/*
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal 4iProto Server
 * File Name    : udp_forward.go
 * Programmer   : Ebrahim Shafiei (EbraSha)
 * Email        : Prof.Shafiei@Gmail.com
 * Created On   : 2026-06-30 04:12:29
 * Description  : SSH direct-udpip channel forwarding with length-prefixed datagram framing
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

package sshserver

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"Abdal_4iProto_Server/core/config"
	"Abdal_4iProto_Server/core/logging"
	"Abdal_4iProto_Server/core/security"

	"golang.org/x/crypto/ssh"
)

// HandleDirectUDPIP forwards a direct-udpip SSH channel using length-prefixed datagram framing.
func (h *Handler) HandleDirectUDPIP(newChannel ssh.NewChannel, username, userIP string) {
	type directUDPIPReq struct {
		HostToConnect     string
		PortToConnect     uint32
		OriginatorAddress string
		OriginatorPort    uint32
	}

	user, _ := config.GetUser(username)
	maxTotalMB := user.MaxTotalMB
	userLimiter := h.Traffic.GetRateLimiter(username)
	serverCfg := config.Server()

	var req directUDPIPReq
	if err := ssh.Unmarshal(newChannel.ExtraData(), &req); err != nil {
		newChannel.Reject(ssh.Prohibited, "bad direct-udpip request")
		return
	}

	if security.IsDomainOrIPBlocked(username, req.HostToConnect) {
		log.Printf("🚫 User %s tried to access blocked UDP target: %s", username, req.HostToConnect)
		logging.BlockedAccess(username, req.HostToConnect, userIP)
		newChannel.Reject(ssh.Prohibited, "access to this domain/IP is blocked")
		return
	}

	logging.UserAccess(username, req.HostToConnect, userIP)

	addrStr := net.JoinHostPort(req.HostToConnect, fmt.Sprintf("%d", req.PortToConnect))
	udpAddr, err := net.ResolveUDPAddr("udp", addrStr)
	if err != nil {
		newChannel.Reject(ssh.ConnectionFailed, "resolve failed")
		return
	}

	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		newChannel.Reject(ssh.ConnectionFailed, "udp connect failed")
		return
	}

	socketBufBytes := serverCfg.UDPSocketBufferBytes()
	_ = udpConn.SetReadBuffer(socketBufBytes)
	_ = udpConn.SetWriteBuffer(socketBufBytes)
	idleTimeoutSecs := serverCfg.UDPIdleTimeoutSeconds()

	channel, requests, err := newChannel.Accept()
	if err != nil {
		udpConn.Close()
		return
	}
	go ssh.DiscardRequests(requests)

	log.Printf("📡 UDP tunnel opened for %s → %s", username, addrStr)

	var bytesSent atomic.Int64
	var bytesReceived atomic.Int64
	var lastSent int64
	var lastReceived int64
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().Unix())

	limitExceeded := make(chan bool, 1)
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		const saveEveryNTicks = 5
		tickCount := 0
		for {
			select {
			case <-ticker.C:
				currentSent := bytesSent.Load()
				currentReceived := bytesReceived.Load()
				sentDelta := currentSent - lastSent
				receivedDelta := currentReceived - lastReceived
				if sentDelta > 0 || receivedDelta > 0 {
					if h.Traffic.UpdateRealTime(username, userIP, sentDelta, receivedDelta, maxTotalMB) {
						select {
						case limitExceeded <- true:
						default:
						}
						log.Printf("🚫 User %s exceeded traffic limit, closing UDP connection", username)
						channel.Close()
						udpConn.Close()
						return
					}
					tickCount++
					if tickCount >= saveEveryNTicks {
						h.Traffic.SaveToFile(username)
						tickCount = 0
					}
					lastSent = currentSent
					lastReceived = currentReceived
				}
			case <-done:
				return
			case <-limitExceeded:
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		defer udpConn.Close()
		defer channel.CloseWrite()

		var hdr [2]byte
		payload := make([]byte, config.UDPMaxDatagramSize)

		for {
			select {
			case <-limitExceeded:
				return
			default:
			}
			if _, err := io.ReadFull(channel, hdr[:]); err != nil {
				return
			}
			n := int(binary.BigEndian.Uint16(hdr[:]))
			if n == 0 {
				lastActivity.Store(time.Now().Unix())
				continue
			}
			if n > config.UDPMaxDatagramSize {
				return
			}
			if _, err := io.ReadFull(channel, payload[:n]); err != nil {
				return
			}
			if userLimiter != nil {
				if err := userLimiter.WaitN(context.Background(), n+2); err != nil {
					return
				}
			}
			if _, err := udpConn.Write(payload[:n]); err != nil {
				return
			}
			bytesSent.Add(int64(n + 2))
			lastActivity.Store(time.Now().Unix())
		}
	}()

	go func() {
		defer wg.Done()
		defer channel.Close()

		frame := make([]byte, 2+config.UDPMaxDatagramSize)
		for {
			select {
			case <-limitExceeded:
				return
			default:
			}
			_ = udpConn.SetReadDeadline(time.Now().Add(config.UDPReadTick))
			n, _, err := udpConn.ReadFromUDP(frame[2:])
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					if time.Now().Unix()-lastActivity.Load() > idleTimeoutSecs {
						return
					}
					continue
				}
				return
			}
			if n == 0 {
				continue
			}
			binary.BigEndian.PutUint16(frame[:2], uint16(n))
			if userLimiter != nil {
				if err := userLimiter.WaitN(context.Background(), n+2); err != nil {
					return
				}
			}
			if _, err := channel.Write(frame[:2+n]); err != nil {
				return
			}
			bytesReceived.Add(int64(n + 2))
			lastActivity.Store(time.Now().Unix())
		}
	}()

	wg.Wait()
	close(done)

	log.Printf("🔌 UDP tunnel closed for %s → %s", username, addrStr)

	sent := bytesSent.Load()
	received := bytesReceived.Load()
	if sent > lastSent || received > lastReceived {
		h.Traffic.UpdateRealTime(username, userIP, sent-lastSent, received-lastReceived, maxTotalMB)
		h.Traffic.SaveToFile(username)
	}
	h.Traffic.UpdateSessionFinalStats(username, sent, received)
}
