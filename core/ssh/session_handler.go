/*
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal 4iProto Server
 * File Name    : session_handler.go
 * Programmer   : Ebrahim Shafiei (EbraSha)
 * Email        : Prof.Shafiei@Gmail.com
 * Created On   : 2026-06-30 04:12:29
 * Description  : Interactive SSH session handling with role-based shell access
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

package sshserver

import (
	"Abdal_4iProto_Server/core/config"
	"Abdal_4iProto_Server/core/shell"

	"golang.org/x/crypto/ssh"
)

// HandleSession processes SSH session channel requests including PTY and shell.
func (h *Handler) HandleSession(channel ssh.Channel, requests <-chan *ssh.Request, username string) {
	defer channel.Close()
	hasPty := false
	winCh := make(chan *shell.WindowSize, 1)

	user, exists := config.GetUser(username)
	if !exists {
		channel.Write([]byte("❌ User not found\n"))
		return
	}

	for req := range requests {
		switch req.Type {
		case "pty-req":
			hasPty = true
			if req.WantReply {
				req.Reply(true, nil)
			}

		case "window-change":
			if len(req.Payload) >= 16 {
				width := uint32(req.Payload[0])<<24 | uint32(req.Payload[1])<<16 | uint32(req.Payload[2])<<8 | uint32(req.Payload[3])
				height := uint32(req.Payload[4])<<24 | uint32(req.Payload[5])<<16 | uint32(req.Payload[6])<<8 | uint32(req.Payload[7])
				pixelWidth := uint32(req.Payload[8])<<24 | uint32(req.Payload[9])<<16 | uint32(req.Payload[10])<<8 | uint32(req.Payload[11])
				pixelHeight := uint32(req.Payload[12])<<24 | uint32(req.Payload[13])<<16 | uint32(req.Payload[14])<<8 | uint32(req.Payload[15])

				select {
				case winCh <- &shell.WindowSize{Width: width, Height: height, PixelWidth: pixelWidth, PixelHeight: pixelHeight}:
				default:
				}
			}
			if req.WantReply {
				req.Reply(true, nil)
			}

		case "shell":
			if !hasPty {
				if req.WantReply {
					req.Reply(false, nil)
				}
				continue
			}

			if user.Role != "admin" {
				channel.Write([]byte("❌ Access Denied: Shell access is restricted to admin users only\n"))
				channel.Write([]byte("ℹ️  Your role: " + user.Role + "\n"))
				channel.Write([]byte("ℹ️  You can still use tunneling features\n"))
				if req.WantReply {
					req.Reply(false, nil)
				}
				continue
			}

			if req.WantReply {
				req.Reply(true, nil)
			}

			asciiBanner := `

░█████╗░██████╗░██████╗░░█████╗░██╗░░░░░  ░░██╗██╗██╗██████╗░██████╗░░█████╗░████████╗░█████╗░
██╔══██╗██╔══██╗██╔══██╗██╔══██╗██║░░░░░  ░██╔╝██║██║██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔══██╗
███████║██████╦╝██║░░██║███████║██║░░░░░  ██╔╝░██║██║██████╔╝██████╔╝██║░░██║░░░██║░░░██║░░██║
██╔══██║██╔══██╗██║░░██║██╔══██║██║░░░░░  ███████║██║██╔═══╝░██╔══██╗██║░░██║░░░██║░░░██║░░██║
██║░░██║██████╦╝██████╔╝██║░░██║███████╗  ╚════██║██║██║░░░░░██║░░██║╚█████╔╝░░░██║░░░╚█████╔╝
╚═╝░░╚═╝╚═════╝░╚═════╝░╚═╝░░╚═╝╚══════╝  ░░░░░╚═╝╚═╝╚═╝░░░░░╚═╝░░╚═╝░╚════╝░░░░╚═╝░░░░╚════╝░

░██████╗███████╗██████╗░██╗░░░██╗███████╗██████╗░
██╔════╝██╔════╝██╔══██╗██║░░░██║██╔════╝██╔══██╗
╚█████╗░█████╗░░██████╔╝╚██╗░██╔╝█████╗░░██████╔╝
░╚═══██╗██╔══╝░░██╔══██╗░╚████╔╝░██╔══╝░░██╔══██╗
██████╔╝███████╗██║░░██║░░╚██╔╝░░███████╗██║░░██║
╚═════╝░╚══════╝╚═╝░░╚═╝░░░╚═╝░░░╚══════╝╚═╝░░╚═╝

🛡️  Welcome to Abdal 4iProto Server ver 8.20
🧠  Developed by: Ebrahim Shafiei (EbraSha)
✉️ Prof.Shafiei@Gmail.com

`
			channel.Write([]byte(asciiBanner))
			shell.Start(channel, config.Server().Shell, winCh)
			return

		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}
