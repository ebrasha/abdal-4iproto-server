@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

REM **********************************************************************
REM -------------------------------------------------------------------
REM Project Name : Abdal 4iProto Server
REM File Name    : abdal-service-manager.bat
REM Author       : Ebrahim Shafiei (EbraSha)
REM Email        : Prof.Shafiei@Gmail.com
REM Created On   : 2025-09-30 01:15:59
REM Description  : Windows Service Manager for Abdal 4iProto Server - Install/Uninstall service with admin privileges
REM -------------------------------------------------------------------
REM
REM "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
REM – Ebrahim Shafiei
REM
REM **********************************************************************

:: Set console color scheme
color 0F

:: Service configuration
set "SERVICE_NAME=Abdal4iProtoServer"
set "SERVICE_DISPLAY_NAME=Abdal 4iProto Server"
set "SERVICE_DESCRIPTION=Abdal 4iProto Server - Advanced Network Protocol Service"
set "EXECUTABLE_NAME=abdal-4iproto-server-windows.exe"
set "CURRENT_DIR=%~dp0"

:: Check for admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    color 0C
    echo [ERROR] This script requires administrator privileges!
    color 0E
    echo [INFO] Please run this script as Administrator.
    echo.
    color 0B
    echo [SOLUTION] Right-click on this file and select "Run as administrator"
    echo.
    color 0F
    pause
    exit /b 1
)

:MAIN_MENU
cls
color 0B
echo.
echo ╔══════════════════════════════════════════════════════════════╗
echo ║                ABDAL 4IPROTO SERVER MANAGER                  ║
echo ║                                                              ║
color 0A
echo ║  1. Install Service                                          ║
color 0C
echo ║  2. Stop and Remove Service                                  ║
color 0E
echo ║  3. Check Service Status                                     ║
color 0D
echo ║  4. Exit                                                     ║
color 0B
echo ╚══════════════════════════════════════════════════════════════╝
echo.
color 0F
set /p choice=Please select an option (1-4): 

if "%choice%"=="1" goto INSTALL_SERVICE
if "%choice%"=="2" goto REMOVE_SERVICE
if "%choice%"=="3" goto CHECK_STATUS
if "%choice%"=="4" goto EXIT
color 0C
echo [ERROR] Invalid choice! Please select 1, 2, 3, or 4.
color 0F
timeout /t 2 >nul
goto MAIN_MENU

:INSTALL_SERVICE
cls
color 0B
echo.
echo ╔══════════════════════════════════════════════════════════════╗
color 0A
echo ║                    INSTALLING SERVICE                       ║
color 0B
echo ╚══════════════════════════════════════════════════════════════╝
echo.

:: Check if executable exists
if not exist "%CURRENT_DIR%%EXECUTABLE_NAME%" (
    color 0C
    echo [ERROR] Executable file not found: %EXECUTABLE_NAME%
    color 0E
    echo [INFO] Please ensure the executable is in the same directory as this script.
    echo [INFO] Current directory: %CURRENT_DIR%
    echo.
    color 0F
    pause
    goto MAIN_MENU
)

:: Check if service already exists
sc query "%SERVICE_NAME%" >nul 2>&1
if %errorLevel% equ 0 (
    color 0E
    echo [WARNING] Service "%SERVICE_NAME%" already exists!
    color 0B
    echo [INFO] Stopping and removing existing service...
    
    :: Stop the service
    sc stop "%SERVICE_NAME%" >nul 2>&1
    timeout /t 3 >nul
    
    :: Delete the service
    sc delete "%SERVICE_NAME%" >nul 2>&1
    if %errorLevel% equ 0 (
        color 0A
        echo [SUCCESS] Existing service removed successfully.
    ) else (
        color 0C
        echo [ERROR] Failed to remove existing service.
        echo.
        color 0F
        pause
        goto MAIN_MENU
    )
    echo.
)

:: Install the service
color 0B
echo [INFO] Installing service "%SERVICE_NAME%"...
sc create "%SERVICE_NAME%" binPath= "\"%CURRENT_DIR%%EXECUTABLE_NAME%\" -service" DisplayName= "%SERVICE_DISPLAY_NAME%" start= auto

if %errorLevel% equ 0 (
    color 0A
    echo [SUCCESS] Service created successfully!
    
    :: Set service description
    sc description "%SERVICE_NAME%" "%SERVICE_DESCRIPTION%"
    
    :: Start the service
    color 0B
    echo [INFO] Starting service...
    sc start "%SERVICE_NAME%"
    
    if %errorLevel% equ 0 (
        color 0A
        echo [SUCCESS] Service started successfully!
        echo.
        echo [COMPLETE] Abdal 4iProto Server is now running as a Windows service.
        color 0B
        echo [INFO] Service will start automatically on system boot.
    ) else (
        color 0E
        echo [WARNING] Service created but failed to start.
        color 0B
        echo [INFO] You can start it manually from Services.msc
    )
) else (
    color 0C
    echo [ERROR] Failed to create service!
    color 0E
    echo [INFO] Please check the executable path and permissions.
)

echo.
pause
goto MAIN_MENU

:REMOVE_SERVICE
cls
color 0B
echo.
echo ╔══════════════════════════════════════════════════════════════╗
color 0C
echo ║                   REMOVING SERVICE                          ║
color 0B
echo ╚══════════════════════════════════════════════════════════════╝
echo.

:: Check if service exists
sc query "%SERVICE_NAME%" >nul 2>&1
if %errorLevel% neq 0 (
    color 0E
    echo [WARNING] Service "%SERVICE_NAME%" does not exist.
    color 0B
    echo [INFO] Nothing to remove.
    echo.
    color 0F
    pause
    goto MAIN_MENU
)

:: Stop the service
color 0B
echo [INFO] Stopping service "%SERVICE_NAME%"...
sc stop "%SERVICE_NAME%" >nul 2>&1

if %errorLevel% equ 0 (
    color 0A
    echo [SUCCESS] Service stopped successfully.
) else (
    color 0E
    echo [WARNING] Service may already be stopped or failed to stop.
)

:: Wait a moment for service to fully stop
timeout /t 3 >nul

:: Delete the service
color 0B
echo [INFO] Removing service "%SERVICE_NAME%"...
sc delete "%SERVICE_NAME%" >nul 2>&1

if %errorLevel% equ 0 (
    color 0A
    echo [SUCCESS] Service removed successfully!
    color 0B
    echo [INFO] Abdal 4iProto Server service has been completely removed.
) else (
    color 0C
    echo [ERROR] Failed to remove service!
    color 0E
    echo [INFO] You may need to restart your computer to complete the removal.
)

echo.
pause
goto MAIN_MENU

:CHECK_STATUS
cls
color 0B
echo.
echo ╔══════════════════════════════════════════════════════════════╗
color 0F
echo ║                   SERVICE STATUS                            ║
color 0B
echo ╚══════════════════════════════════════════════════════════════╝
echo.

:: Check if service exists
sc query "%SERVICE_NAME%" >nul 2>&1
if %errorLevel% neq 0 (
    color 0C
    echo [STATUS] Service "%SERVICE_NAME%" is NOT INSTALLED
    echo.
    color 0F
    pause
    goto MAIN_MENU
)

:: Get service status
for /f "tokens=3 delims=: " %%H in ('sc query "%SERVICE_NAME%" ^| findstr "        STATE"') do (
    if /i "%%H"=="RUNNING" (
        color 0A
        echo [STATUS] Service "%SERVICE_NAME%" is RUNNING
    ) else if /i "%%H"=="STOPPED" (
        color 0E
        echo [STATUS] Service "%SERVICE_NAME%" is STOPPED
    ) else (
        color 0B
        echo [STATUS] Service "%SERVICE_NAME%" is %%H
    )
)

:: Get startup type
for /f "tokens=3 delims=: " %%H in ('sc qc "%SERVICE_NAME%" ^| findstr "        START_TYPE"') do (
    if /i "%%H"=="AUTO_START" (
        color 0A
        echo [STARTUP] Service is set to AUTOMATIC startup
    ) else if /i "%%H"=="DEMAND_START" (
        color 0E
        echo [STARTUP] Service is set to MANUAL startup
    ) else (
        color 0B
        echo [STARTUP] Service startup type: %%H
    )
)

echo.
color 0B
echo [INFO] You can manage this service from Services.msc (services.msc)
echo.
color 0F
pause
goto MAIN_MENU

:EXIT
cls
color 0B
echo.
echo ╔══════════════════════════════════════════════════════════════╗
color 0A
echo ║                      THANK YOU!                             ║
color 0B
echo ║                                                              ║
color 0F
echo ║  Abdal 4iProto Server Service Manager                       ║
echo ║  Developed by: Ebrahim Shafiei (EbraSha)                    ║
echo ║  Email: Prof.Shafiei@Gmail.com                              ║
color 0B
echo ╚══════════════════════════════════════════════════════════════╝
echo.
color 0A
echo [INFO] Goodbye! Have a great day!
echo.
color 0F
pause
exit /b 0
