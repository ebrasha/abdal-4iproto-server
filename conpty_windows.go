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

// Start interactive shell on Windows using ConPTY
func startShell(channel ssh.Channel, shell string) {
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
