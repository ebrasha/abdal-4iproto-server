/*
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal 4iProto Server
 * File Name    : conpty_other.go
 * Programmer   : Ebrahim Shafiei (EbraSha)
 * Email        : Prof.Shafiei@Gmail.com
 * Created On   : 2026-06-30 04:12:29
 * Description  : Linux/Unix shell support using PTY for interactive terminal sessions
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

//go:build !windows

package shell

import (
	"io"
	"log"
	"os"
	"os/exec"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
)

// WindowSize carries terminal size from SSH "window-change".
type WindowSize struct {
	Width       uint32
	Height      uint32
	PixelWidth  uint32
	PixelHeight uint32
}

// Start launches an interactive shell on Linux/Unix systems using PTY.
func Start(channel ssh.Channel, shellCmd string, winCh <-chan *WindowSize) {
	cmd := exec.Command(shellCmd)
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")

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

	log.Printf("✅ Started shell process: %s (PID: %d) with PTY", shellCmd, cmd.Process.Pid)

	go func() {
		_, _ = io.Copy(ptmx, channel)
	}()
	go func() {
		_, _ = io.Copy(channel, ptmx)
	}()
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

	if err := cmd.Wait(); err != nil {
		log.Printf("shell exited with error: %v", err)
	} else {
		log.Printf("shell exited normally")
	}
	_ = channel.Close()
}
