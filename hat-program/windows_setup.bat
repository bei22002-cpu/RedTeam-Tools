@echo off
:: =============================================================
:: Hat Program - Windows Setup & WSL Installer
:: =============================================================
:: This script installs WSL (Windows Subsystem for Linux) with
:: Ubuntu, clones the repo inside WSL, installs dependencies,
:: and launches the Hat Program.
::
:: Run this as Administrator (right-click > Run as administrator)
:: =============================================================

title Hat Program - Windows Setup
color 0A

echo.
echo  ============================================================
echo   Hat Program - Windows WSL Setup
echo  ============================================================
echo.
echo  This will:
echo    1. Enable WSL (Windows Subsystem for Linux)
echo    2. Install Ubuntu on WSL
echo    3. Set up the Hat Program inside Linux
echo.
echo  REQUIRES: Administrator privileges and Windows 10/11
echo.

:: Check for admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] This script must be run as Administrator!
    echo  Right-click this file and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

echo  [+] Administrator privileges confirmed.
echo.

:: Check if WSL is already installed
wsl --status >nul 2>&1
if %errorlevel% equ 0 (
    echo  [+] WSL is already installed.
    goto :check_ubuntu
)

echo  [*] Installing WSL...
echo  [*] This may take a few minutes and require a restart.
echo.
wsl --install --no-launch
if %errorlevel% neq 0 (
    echo.
    echo  [!] WSL install command ran. If this is the first time,
    echo      you may need to RESTART your computer, then run
    echo      this script again.
    echo.
    pause
    exit /b 0
)

:check_ubuntu
:: Check if Ubuntu is available
wsl -l -q 2>nul | findstr /i "Ubuntu" >nul 2>&1
if %errorlevel% equ 0 (
    echo  [+] Ubuntu is already installed in WSL.
    goto :setup_program
)

echo  [*] Installing Ubuntu in WSL...
wsl --install -d Ubuntu --no-launch
if %errorlevel% neq 0 (
    echo  [!] Ubuntu installation started. You may need to restart
    echo      your computer and run this script again.
    pause
    exit /b 0
)

:: Initialize Ubuntu (first run sets up the default user)
echo.
echo  [*] Initializing Ubuntu...
echo  [*] You will be asked to create a Linux username and password.
echo      Remember these - you will need them for sudo commands.
echo.
wsl -d Ubuntu echo "Ubuntu initialized successfully"

:setup_program
echo.
echo  [*] Setting up Hat Program inside WSL...
echo.

:: Get the Windows path to this repo and convert to WSL path
set "WIN_PATH=%~dp0"
:: Remove trailing backslash
set "WIN_PATH=%WIN_PATH:~0,-1%"

:: Run setup inside WSL
wsl -d Ubuntu bash -c "echo '=== Hat Program Linux Setup ===' && sudo apt-get update -qq && sudo apt-get install -y -qq python3 git curl net-tools nmap dnsutils whois openssl 2>/dev/null && echo '[+] Dependencies installed' && echo '[+] Setup complete!'"

if %errorlevel% neq 0 (
    echo  [!] Setup had some issues, but the program may still work.
    echo      Some optional tools may not be available.
)

echo.
echo  ============================================================
echo   Setup Complete! 
echo  ============================================================
echo.
echo  To run the Hat Program, use:
echo    run_hat_program.bat
echo.
echo  Or manually:
echo    wsl -d Ubuntu python3 %WIN_PATH%\hat_program.py
echo.
echo  For full features (run as root in WSL):
echo    wsl -d Ubuntu sudo python3 %WIN_PATH%\hat_program.py
echo.
pause
