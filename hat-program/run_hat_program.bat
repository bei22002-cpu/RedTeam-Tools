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

:: Check if Ubuntu is installed
wsl -l -q 2>nul | findstr /i "Ubuntu" >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo  [ERROR] Ubuntu is not installed in WSL.
    echo  Run windows_setup.bat first to install Ubuntu.
    echo.
    pause
    exit /b 1
)

:: Get the directory this script is in
set "SCRIPT_DIR=%~dp0"

:: Convert Windows path to WSL path
for /f "tokens=*" %%i in ('wsl -d Ubuntu wslpath -a "%SCRIPT_DIR%"') do set "WSL_PATH=%%i"

:: Launch the program
echo.
echo  Starting Hat Program in WSL...
echo.
wsl -d Ubuntu bash -c "cd '%WSL_PATH%' && python3 hat_program.py"

pause
