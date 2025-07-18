//go:build !windows

package main

import "golang.org/x/crypto/ssh"

// Dummy shell for non-Windows platforms
func startShell(channel ssh.Channel, shell string) {
	channel.Write([]byte("❌ Interactive shell not supported on Linux in this build.\r\n"))
}
