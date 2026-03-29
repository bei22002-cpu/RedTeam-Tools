@echo off
:: =============================================================
:: Hat Program - Quick Launcher (runs in WSL)
:: =============================================================
:: Double-click this file to launch the Hat Program in WSL.
:: Run windows_setup.bat first if you haven't set up WSL yet.
:: =============================================================

title Hat Program

:: Check if WSL is available
wsl --status >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo  [ERROR] WSL is not installed.
    echo  Run windows_setup.bat first to set up WSL and Ubuntu.
    echo.
    pause
    exit /b 1
)

:: Check if Ubuntu is available by trying to run a command in it
wsl -d Ubuntu echo "ok" >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo  [ERROR] Ubuntu is not available in WSL.
    echo  Run windows_setup.bat as Administrator first.
    echo.
    pause
    exit /b 1
)

:: Get the full path to hat_program.py (same folder as this .bat file)
set "SCRIPT_DIR=%~dp0"
set "PROGRAM=%SCRIPT_DIR%hat_program.py"

:: Launch the program using the full Windows path passed to WSL
echo.
echo  Starting Hat Program in WSL...
echo.
wsl -d Ubuntu bash -c "python3 \"$(wslpath '%PROGRAM%')\""

pause
