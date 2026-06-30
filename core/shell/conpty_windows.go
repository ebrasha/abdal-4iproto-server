/*
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal 4iProto Server
 * File Name    : conpty_windows.go
 * Programmer   : Ebrahim Shafiei (EbraSha)
 * Email        : Prof.Shafiei@Gmail.com
 * Created On   : 2026-06-30 04:12:29
 * Description  : Windows shell support using ConPTY for interactive terminal sessions
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

//go:build windows

package shell

import (
	"context"
	"io"
	"log"
	"os"

	"github.com/UserExistsError/conpty"
	"golang.org/x/crypto/ssh"
)

// WindowSize carries terminal size from SSH "window-change".
type WindowSize struct {
	Width       uint32
	Height      uint32
	PixelWidth  uint32
	PixelHeight uint32
}

// Start launches an interactive shell on Windows using ConPTY.
func Start(channel ssh.Channel, shellCmd string, winCh <-chan *WindowSize) {
	winDir := os.Getenv("SystemRoot")
	fullPath := winDir + "\\System32\\" + shellCmd
	cpty, err := conpty.Start(fullPath)
	if err != nil {
		log.Printf("conpty.Start error: %v", err)
		channel.Write([]byte("❌ Failed to start terminal session\r\n"))
		return
	}
	defer cpty.Close()

	go io.Copy(channel, cpty)
	go io.Copy(cpty, channel)

	exitCode, err := cpty.Wait(context.Background())
	log.Printf("Session exited with code %d, err=%v", exitCode, err)
}
