/*
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal 4iProto Server
 * File Name    : windows_service.go
 * Author       : Ebrahim Shafiei (EbraSha)
 * Email        : Prof.Shafiei@Gmail.com
 * Created On   : 2025-01-27 15:30:00
 * Description  : Windows Service functionality for Abdal 4iProto Server
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
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	serviceName        = "Abdal4iProtoServer"
	serviceDisplayName = "Abdal 4iProto Server"
	serviceDescription = "High-performance SSH-based tunneling server with advanced security features"
)

// WindowsService implements the Windows service interface
type WindowsService struct {
	ctx    context.Context
	cancel context.CancelFunc
}

// Execute is the main service entry point
func (ws *WindowsService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue
	changes <- svc.Status{State: svc.StartPending}

	// Create context for graceful shutdown
	ws.ctx, ws.cancel = context.WithCancel(context.Background())

	// Channel to signal when server is ready
	serverReady := make(chan bool, 1)
	serverError := make(chan error, 1)

	// Start the server in a goroutine
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("❌ Server panic recovered: %v", r)
				select {
				case serverError <- fmt.Errorf("server panic: %v", r):
				default:
				}
			}
		}()
		
		// Call the main server function
		// startServer() is blocking, so we signal ready after initialization
		// Give server time to load configs and start listeners
		go func() {
			time.Sleep(3 * time.Second) // Give server time to initialize listeners
			select {
			case serverReady <- true:
			default:
			}
		}()
		
		startServer()
	}()

	// Wait for server to be ready or timeout (max 25 seconds to avoid Windows timeout)
	select {
	case <-serverReady:
		// Server initialized successfully
		changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
		LogToEventLog("Abdal 4iProto Server service started successfully")
	case err := <-serverError:
		// Server failed to start
		LogToEventLog(fmt.Sprintf("Abdal 4iProto Server service failed to start: %v", err))
		changes <- svc.Status{State: svc.Stopped}
		return false, 1
	case <-time.After(25 * time.Second):
		// Timeout - mark as running to avoid service manager timeout (1053 error)
		// The server is likely still initializing or already running
		changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
		LogToEventLog("Abdal 4iProto Server service starting (initialization timeout, but continuing)")
	case <-ws.ctx.Done():
		// Context cancelled before start
		changes <- svc.Status{State: svc.Stopped}
		return false, 1
	}

	// Service control loop
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
				time.Sleep(100 * time.Millisecond)
				changes <- c.CurrentStatus

			case svc.Stop, svc.Shutdown:
				log.Println("🛑 Service stop/shutdown requested")
				changes <- svc.Status{State: svc.StopPending}
				ws.cancel() // Signal shutdown
				return

			case svc.Pause:
				log.Println("⏸️ Service pause requested")
				changes <- svc.Status{State: svc.Paused, Accepts: cmdsAccepted}

			case svc.Continue:
				log.Println("▶️ Service continue requested")
				changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

			default:
				log.Printf("⚠️ Unexpected service control request: %d", c.Cmd)
			}

		case <-ws.ctx.Done():
			log.Println("✅ Service context cancelled, shutting down")
			return
		}
	}
}

// InstallService installs the Windows service
func InstallService() error {
	// Get the executable path
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	// Resolve symlinks
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return fmt.Errorf("failed to resolve symlinks: %w", err)
	}

	// Connect to service manager
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	// Check if service already exists
	service, err := m.OpenService(serviceName)
	if err == nil {
		service.Close()
		return fmt.Errorf("service %s already exists", serviceName)
	}

	// Create the service
	service, err = m.CreateService(
		serviceName,
		exePath,
		mgr.Config{
			DisplayName:      serviceDisplayName,
			Description:      serviceDescription,
			StartType:        mgr.StartAutomatic,
			ServiceStartName: "LocalSystem",
		},
		"-service", // Add service flag
	)
	if err != nil {
		return fmt.Errorf("failed to create service: %w", err)
	}
	defer service.Close()

	// Set service recovery options
	err = service.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 120 * time.Second},
	}, 86400) // Reset after 24 hours
	if err != nil {
		log.Printf("⚠️ Failed to set recovery actions: %v", err)
	}

	log.Printf("✅ Service %s installed successfully", serviceName)
	log.Printf("📋 Display Name: %s", serviceDisplayName)
	log.Printf("📝 Description: %s", serviceDescription)
	log.Printf("🚀 Start Type: Automatic")
	log.Printf("🔧 Executable: %s", exePath)

	return nil
}

// UninstallService removes the Windows service
func UninstallService() error {
	// Connect to service manager
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	// Open the service
	service, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", serviceName)
	}
	defer service.Close()

	// Stop the service if it's running
	status, err := service.Query()
	if err == nil && status.State != svc.Stopped {
		log.Printf("🛑 Stopping service %s...", serviceName)
		_, err = service.Control(svc.Stop)
		if err != nil {
			log.Printf("⚠️ Failed to stop service: %v", err)
		} else {
			// Wait for service to stop
			for {
				status, err := service.Query()
				if err != nil || status.State == svc.Stopped {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
	}

	// Delete the service
	err = service.Delete()
	if err != nil {
		return fmt.Errorf("failed to delete service: %w", err)
	}

	log.Printf("✅ Service %s uninstalled successfully", serviceName)
	return nil
}

// StartService starts the Windows service
func StartService() error {
	// Connect to service manager
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	// Open the service
	service, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", serviceName)
	}
	defer service.Close()

	// Start the service
	err = service.Start()
	if err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	log.Printf("✅ Service %s started successfully", serviceName)
	return nil
}

// StopService stops the Windows service
func StopService() error {
	// Connect to service manager
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	// Open the service
	service, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", serviceName)
	}
	defer service.Close()

	// Stop the service
	_, err = service.Control(svc.Stop)
	if err != nil {
		return fmt.Errorf("failed to stop service: %w", err)
	}

	log.Printf("✅ Service %s stopped successfully", serviceName)
	return nil
}

// GetServiceStatus returns the current status of the Windows service
func GetServiceStatus() (string, error) {
	// Connect to service manager
	m, err := mgr.Connect()
	if err != nil {
		return "", fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	// Open the service
	service, err := m.OpenService(serviceName)
	if err != nil {
		return "", fmt.Errorf("service %s is not installed", serviceName)
	}
	defer service.Close()

	// Query service status
	status, err := service.Query()
	if err != nil {
		return "", fmt.Errorf("failed to query service status: %w", err)
	}

	var statusText string
	switch status.State {
	case svc.Stopped:
		statusText = "Stopped"
	case svc.StartPending:
		statusText = "Starting"
	case svc.StopPending:
		statusText = "Stopping"
	case svc.Running:
		statusText = "Running"
	case svc.ContinuePending:
		statusText = "Continuing"
	case svc.PausePending:
		statusText = "Pausing"
	case svc.Paused:
		statusText = "Paused"
	default:
		statusText = "Unknown"
	}

	return statusText, nil
}

// SetupEventLog creates event log source for the service
func SetupEventLog() error {
	// Get the executable path
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	// Resolve symlinks
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return fmt.Errorf("failed to resolve symlinks: %w", err)
	}

	// Create event log source
	err = eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info)
	if err != nil {
		// If already exists, that's okay
		if !strings.Contains(err.Error(), "already exists") {
			return fmt.Errorf("failed to create event log source: %w", err)
		}
	}

	log.Printf("✅ Event log source %s configured", serviceName)
	return nil
}

// RemoveEventLog removes event log source
func RemoveEventLog() error {
	err := eventlog.Remove(serviceName)
	if err != nil {
		return fmt.Errorf("failed to remove event log source: %w", err)
	}

	log.Printf("✅ Event log source %s removed", serviceName)
	return nil
}

// LogToEventLog writes a message to Windows Event Log
func LogToEventLog(msg string) {
	el, err := eventlog.Open(serviceName)
	if err != nil {
		log.Printf("⚠️ Failed to open event log: %v", err)
		return
	}
	defer el.Close()

	err = el.Info(1, msg)
	if err != nil {
		log.Printf("⚠️ Failed to write to event log: %v", err)
	}
}

// HandleServiceCommands processes service-related command line arguments
func HandleServiceCommands() bool {
	if len(os.Args) < 2 {
		return false
	}

	cmd := strings.ToLower(os.Args[1])
	
	switch cmd {
	case "-install", "--install", "install":
		fmt.Println("🔧 Installing Abdal 4iProto Server as Windows Service...")
		if err := SetupEventLog(); err != nil {
			log.Printf("⚠️ Failed to setup event log: %v", err)
		}
		if err := InstallService(); err != nil {
			log.Fatalf("❌ Failed to install service: %v", err)
		}
		fmt.Println("✅ Service installed successfully!")
		fmt.Println("📋 You can now start the service using:")
		fmt.Printf("   net start %s\n", serviceName)
		fmt.Println("   or use Services.msc")
		return true

	case "-uninstall", "--uninstall", "uninstall":
		fmt.Println("🗑️ Uninstalling Abdal 4iProto Server Windows Service...")
		if err := UninstallService(); err != nil {
			log.Fatalf("❌ Failed to uninstall service: %v", err)
		}
		if err := RemoveEventLog(); err != nil {
			log.Printf("⚠️ Failed to remove event log: %v", err)
		}
		fmt.Println("✅ Service uninstalled successfully!")
		return true

	case "-start", "--start", "start":
		fmt.Printf("🚀 Starting %s service...\n", serviceName)
		if err := StartService(); err != nil {
			log.Fatalf("❌ Failed to start service: %v", err)
		}
		fmt.Println("✅ Service started successfully!")
		return true

	case "-stop", "--stop", "stop":
		fmt.Printf("🛑 Stopping %s service...\n", serviceName)
		if err := StopService(); err != nil {
			log.Fatalf("❌ Failed to stop service: %v", err)
		}
		fmt.Println("✅ Service stopped successfully!")
		return true

	case "-status", "--status", "status":
		status, err := GetServiceStatus()
		if err != nil {
			log.Fatalf("❌ Failed to get service status: %v", err)
		}
		fmt.Printf("📊 Service Status: %s\n", status)
		return true

	case "-service", "--service", "service":
		// Run as service
		fmt.Printf("🔄 Running %s as Windows Service...\n", serviceDisplayName)
		
		// Setup event logging
		if err := SetupEventLog(); err != nil {
			log.Printf("⚠️ Failed to setup event log: %v", err)
		}

		// Log service start
		LogToEventLog("Abdal 4iProto Server service starting...")

		// Run the service
		err := svc.Run(serviceName, &WindowsService{})
		if err != nil {
			LogToEventLog(fmt.Sprintf("Service failed: %v", err))
			log.Fatalf("❌ Service failed: %v", err)
		}

		LogToEventLog("Abdal 4iProto Server service stopped")
		return true

	default:
		return false
	}
}

// PrintServiceHelp prints help information for service commands
func PrintServiceHelp() {
	fmt.Println("🔧 Windows Service Commands:")
	fmt.Println("  -install    Install as Windows Service")
	fmt.Println("  -uninstall  Remove Windows Service")
	fmt.Println("  -start      Start the service")
	fmt.Println("  -stop       Stop the service")
	fmt.Println("  -status     Show service status")
	fmt.Println("  -service    Run as service (internal use)")
	fmt.Println("")
	fmt.Println("📋 Examples:")
	fmt.Printf("  %s -install    # Install service\n", os.Args[0])
	fmt.Printf("  %s -start      # Start service\n", os.Args[0])
	fmt.Printf("  %s -status     # Check status\n", os.Args[0])
	fmt.Printf("  %s -uninstall  # Remove service\n", os.Args[0])
}
