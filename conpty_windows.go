/*
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal 4iProto Server
 * File Name    : conpty_windows.go
 * Author       : Ebrahim Shafiei (EbraSha)
 * Email        : Prof.Shafiei@Gmail.com
 * Created On   : 2025-09-10 22:12:41
 * Description  : Windows shell support using ConPTY for interactive terminal sessions
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

//go:build windows

package main

import (
	"context"
	"github.com/UserExistsError/conpty"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"os"
)

// WindowSize carries terminal size from SSH "window-change"
type WindowSize struct {
	Width       uint32
	Height      uint32
	PixelWidth  uint32
	PixelHeight uint32
}

// Start interactive shell on Windows using ConPTY
func startShell(channel ssh.Channel, shell string, winCh <-chan *WindowSize) {
	winDir := os.Getenv("SystemRoot")
	fullPath := winDir + "\\System32\\" + shell
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
