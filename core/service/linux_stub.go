/*
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal 4iProto Server
 * File Name    : linux_stub.go
 * Programmer   : Ebrahim Shafiei (EbraSha)
 * Email        : Prof.Shafiei@Gmail.com
 * Created On   : 2026-06-30 04:12:29
 * Description  : Linux stub for Windows service functionality
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

//go:build !windows

package service

import (
	"fmt"
	"os"
)

// HandleServiceCommands is a stub for non-Windows platforms.
func HandleServiceCommands() bool {
	if len(os.Args) < 2 {
		return false
	}
	cmd := os.Args[1]
	switch cmd {
	case "-install", "--install", "install",
		"-uninstall", "--uninstall", "uninstall",
		"-start", "--start", "start",
		"-stop", "--stop", "stop",
		"-status", "--status", "status",
		"-service", "--service", "service":
		fmt.Println("❌ Windows Service functionality is not available on Linux")
		fmt.Println("ℹ️  This feature is only supported on Windows operating system")
		fmt.Println("ℹ️  You can run the server directly without service installation")
		fmt.Println("")
		fmt.Println("🚀 To run the server on Linux:")
		fmt.Printf("   %s\n", os.Args[0])
		fmt.Println("")
		fmt.Println("📋 For more information, visit:")
		fmt.Println("   https://github.com/ebrasha")
		return true
	default:
		return false
	}
}
