/*
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal 4iProto Server
 * File Name    : windows_service.go
 * Programmer   : Ebrahim Shafiei (EbraSha)
 * Email        : Prof.Shafiei@Gmail.com
 * Created On   : 2026-06-30 04:12:29
 * Description  : Windows Service functionality for Abdal 4iProto Server
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

//go:build windows

package service

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"Abdal_4iProto_Server/core/app"
	"Abdal_4iProto_Server/core/config"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

// WindowsService implements the Windows service interface.
type WindowsService struct {
	ctx    context.Context
	cancel context.CancelFunc
}

// Execute is the main service entry point.
func (ws *WindowsService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue
	changes <- svc.Status{State: svc.StartPending}

	ws.ctx, ws.cancel = context.WithCancel(context.Background())
	serverReady := make(chan bool, 1)
	serverError := make(chan error, 1)

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
		go func() {
			time.Sleep(3 * time.Second)
			select {
			case serverReady <- true:
			default:
			}
		}()
		app.Run()
	}()

	select {
	case <-serverReady:
		changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
		LogToEventLog("Abdal 4iProto Server service started successfully")
	case err := <-serverError:
		LogToEventLog(fmt.Sprintf("Abdal 4iProto Server service failed to start: %v", err))
		changes <- svc.Status{State: svc.Stopped}
		return false, 1
	case <-time.After(25 * time.Second):
		changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
		LogToEventLog("Abdal 4iProto Server service starting (initialization timeout, but continuing)")
	case <-ws.ctx.Done():
		changes <- svc.Status{State: svc.Stopped}
		return false, 1
	}

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
				ws.cancel()
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

// InstallService installs the Windows service.
func InstallService() error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return fmt.Errorf("failed to resolve symlinks: %w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	service, err := m.OpenService(config.ServiceName)
	if err == nil {
		service.Close()
		return fmt.Errorf("service %s already exists", config.ServiceName)
	}

	service, err = m.CreateService(
		config.ServiceName,
		exePath,
		mgr.Config{
			DisplayName:      config.ServiceDisplayName,
			Description:      config.ServiceDescription,
			StartType:        mgr.StartAutomatic,
			ServiceStartName: "LocalSystem",
		},
		"-service",
	)
	if err != nil {
		return fmt.Errorf("failed to create service: %w", err)
	}
	defer service.Close()

	err = service.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 120 * time.Second},
	}, 86400)
	if err != nil {
		log.Printf("⚠️ Failed to set recovery actions: %v", err)
	}

	log.Printf("✅ Service %s installed successfully", config.ServiceName)
	log.Printf("📋 Display Name: %s", config.ServiceDisplayName)
	log.Printf("📝 Description: %s", config.ServiceDescription)
	log.Printf("🚀 Start Type: Automatic")
	log.Printf("🔧 Executable: %s", exePath)
	return nil
}

// UninstallService removes the Windows service.
func UninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	service, err := m.OpenService(config.ServiceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", config.ServiceName)
	}
	defer service.Close()

	status, err := service.Query()
	if err == nil && status.State != svc.Stopped {
		log.Printf("🛑 Stopping service %s...", config.ServiceName)
		_, err = service.Control(svc.Stop)
		if err != nil {
			log.Printf("⚠️ Failed to stop service: %v", err)
		} else {
			for {
				status, err := service.Query()
				if err != nil || status.State == svc.Stopped {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
	}

	if err := service.Delete(); err != nil {
		return fmt.Errorf("failed to delete service: %w", err)
	}
	log.Printf("✅ Service %s uninstalled successfully", config.ServiceName)
	return nil
}

// StartService starts the Windows service.
func StartService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	service, err := m.OpenService(config.ServiceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", config.ServiceName)
	}
	defer service.Close()

	if err := service.Start(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}
	log.Printf("✅ Service %s started successfully", config.ServiceName)
	return nil
}

// StopService stops the Windows service.
func StopService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	service, err := m.OpenService(config.ServiceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", config.ServiceName)
	}
	defer service.Close()

	if _, err := service.Control(svc.Stop); err != nil {
		return fmt.Errorf("failed to stop service: %w", err)
	}
	log.Printf("✅ Service %s stopped successfully", config.ServiceName)
	return nil
}

// GetServiceStatus returns the current status of the Windows service.
func GetServiceStatus() (string, error) {
	m, err := mgr.Connect()
	if err != nil {
		return "", fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	service, err := m.OpenService(config.ServiceName)
	if err != nil {
		return "", fmt.Errorf("service %s is not installed", config.ServiceName)
	}
	defer service.Close()

	status, err := service.Query()
	if err != nil {
		return "", fmt.Errorf("failed to query service status: %w", err)
	}

	switch status.State {
	case svc.Stopped:
		return "Stopped", nil
	case svc.StartPending:
		return "Starting", nil
	case svc.StopPending:
		return "Stopping", nil
	case svc.Running:
		return "Running", nil
	case svc.ContinuePending:
		return "Continuing", nil
	case svc.PausePending:
		return "Pausing", nil
	case svc.Paused:
		return "Paused", nil
	default:
		return "Unknown", nil
	}
}

// SetupEventLog creates event log source for the service.
func SetupEventLog() error {
	err := eventlog.InstallAsEventCreate(config.ServiceName, eventlog.Error|eventlog.Warning|eventlog.Info)
	if err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			return fmt.Errorf("failed to create event log source: %w", err)
		}
	}
	log.Printf("✅ Event log source %s configured", config.ServiceName)
	return nil
}

// RemoveEventLog removes event log source.
func RemoveEventLog() error {
	if err := eventlog.Remove(config.ServiceName); err != nil {
		return fmt.Errorf("failed to remove event log source: %w", err)
	}
	log.Printf("✅ Event log source %s removed", config.ServiceName)
	return nil
}

// LogToEventLog writes a message to Windows Event Log.
func LogToEventLog(msg string) {
	el, err := eventlog.Open(config.ServiceName)
	if err != nil {
		log.Printf("⚠️ Failed to open event log: %v", err)
		return
	}
	defer el.Close()
	if err := el.Info(1, msg); err != nil {
		log.Printf("⚠️ Failed to write to event log: %v", err)
	}
}

// HandleServiceCommands processes service-related command line arguments.
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
		fmt.Printf("   net start %s\n", config.ServiceName)
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
		fmt.Printf("🚀 Starting %s service...\n", config.ServiceName)
		if err := StartService(); err != nil {
			log.Fatalf("❌ Failed to start service: %v", err)
		}
		fmt.Println("✅ Service started successfully!")
		return true

	case "-stop", "--stop", "stop":
		fmt.Printf("🛑 Stopping %s service...\n", config.ServiceName)
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
		fmt.Printf("🔄 Running %s as Windows Service...\n", config.ServiceDisplayName)
		if err := SetupEventLog(); err != nil {
			log.Printf("⚠️ Failed to setup event log: %v", err)
		}
		LogToEventLog("Abdal 4iProto Server service starting...")
		if err := svc.Run(config.ServiceName, &WindowsService{}); err != nil {
			LogToEventLog(fmt.Sprintf("Service failed: %v", err))
			log.Fatalf("❌ Service failed: %v", err)
		}
		LogToEventLog("Abdal 4iProto Server service stopped")
		return true

	default:
		return false
	}
}

// PrintServiceHelp prints help information for service commands.
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
