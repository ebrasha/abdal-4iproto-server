/*
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal 4iProto Server
 * File Name    : conpty_other.go
 * Author       : Ebrahim Shafiei (EbraSha)
 * Email        : Prof.Shafiei@Gmail.com
 * Created On   : 2025-09-10 22:12:41
 * Description  : Linux/Unix shell support using PTY for interactive terminal sessions
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

//go:build !windows

package main

import (
	"golang.org/x/crypto/ssh"
	"github.com/creack/pty"
	"os"
	"os/exec"
	"io"
	"log"
)

// WindowSize carries terminal size from SSH "window-change"
type WindowSize struct {
	Width       uint32
	Height      uint32
	PixelWidth  uint32
	PixelHeight uint32
}

// Start interactive shell on Linux/Unix systems using PTY
func startShell(channel ssh.Channel, shell string, winCh <-chan *WindowSize) {
	cmd := exec.Command(shell)
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")

	// Start the shell attached to a PTY
	ptmx, err := pty.Start(cmd)
	if err != nil {
		log.Printf("failed to start PTY: %v", err)
		_, _ = channel.Write([]byte("❌ Failed to start PTY\r\n"))
		_ = channel.Close()
		return
	}
	defer func() {
		_ = ptmx.Close()
	}()

	log.Printf("✅ Started shell process: %s (PID: %d) with PTY", shell, cmd.Process.Pid)

	// Bidirectional copy: SSH channel <-> PTY
	// From client to shell
	go func() {
		_, _ = io.Copy(ptmx, channel)
	}()

	// From shell to client
	go func() {
		_, _ = io.Copy(channel, ptmx)
	}()

	// Handle terminal resize events
	go func() {
		for ws := range winCh {
			_ = pty.Setsize(ptmx, &pty.Winsize{
				Cols: uint16(ws.Width),
				Rows: uint16(ws.Height),
				X:    uint16(ws.PixelWidth),
				Y:    uint16(ws.PixelHeight),
			})
		}
	}()

	// Wait for shell to exit
	if err := cmd.Wait(); err != nil {
		log.Printf("shell exited with error: %v", err)
	} else {
		log.Printf("shell exited normally")
	}
	_ = channel.Close()
}
