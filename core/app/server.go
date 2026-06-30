/*
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal 4iProto Server
 * File Name    : server.go
 * Programmer   : Ebrahim Shafiei (EbraSha)
 * Email        : Prof.Shafiei@Gmail.com
 * Created On   : 2026-06-30 04:12:29
 * Description  : Application bootstrap and SSH listener orchestration
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

package app

import (
	"fmt"
	"log"
	"net"
	"time"

	"Abdal_4iProto_Server/core/config"
	"Abdal_4iProto_Server/core/dnstt"
	"Abdal_4iProto_Server/core/security"
	"Abdal_4iProto_Server/core/session"
	sshserver "Abdal_4iProto_Server/core/ssh"
	"Abdal_4iProto_Server/core/traffic"
)

// Run starts the Abdal 4iProto Server (blocking).
func Run() {
	trafficStore := traffic.NewStore()
	guard := security.NewGuard()

	config.LoadUsers(func(username string, maxSpeedKBPS int) {
		trafficStore.InitRateLimiter(username, maxSpeedKBPS)
	})
	config.LoadServerConfig()
	guard.LoadBlockedIPs()
	trafficStore.LoadExistingFiles()

	sm := session.GetManager()
	sm.StartCleanupRoutine()

	handler := &sshserver.Handler{
		Sessions: sm,
		Traffic:  trafficStore,
		Guard:    guard,
	}
	sshConfig := handler.BuildServerConfig()

	serverCfg := config.Server()
	if serverCfg.DNSTTEnabled {
		go dnstt.StartGateway(serverCfg, guard)
	}

	for _, port := range serverCfg.Ports {
		go func(p int) {
			listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", p))
			if err != nil {
				log.Printf("❌ Failed to listen on port %d: %v", p, err)
				return
			}
			defer listener.Close()

			log.Printf("🚀 Abdal 4iProto Server listening on port %d", p)

			for {
				conn, err := listener.Accept()
				if err != nil {
					log.Printf("❌ Failed to accept connection on port %d: %v", p, err)
					continue
				}
				if tcpConn, ok := conn.(*net.TCPConn); ok {
					tcpConn.SetNoDelay(true)
					tcpConn.SetKeepAlive(true)
					tcpConn.SetKeepAlivePeriod(30 * time.Second)
				}
				go handler.HandleConnection(conn, sshConfig)
			}
		}(port)
	}

	trafficStore.StartAutoSave()
	trafficStore.StartDebugTicker()

	select {}
}
