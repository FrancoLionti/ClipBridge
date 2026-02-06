@echo off
:: ClipBridge Windows Startup Script
:: Run this as Administrator to add to startup

echo ============================================
echo ClipBridge - Windows Startup Setup
echo ============================================

:: Get the script directory
set SCRIPT_DIR=%~dp0..
set PYTHON_PATH=python

:: Check if Python is available
%PYTHON_PATH% --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found in PATH
    echo Please install Python or add it to your PATH
    pause
    exit /b 1
)

:: Create a VBS wrapper to run hidden (no console window)
echo Creating hidden launcher...
set VBS_FILE=%SCRIPT_DIR%\clipbridge_hidden.vbs

echo Set WshShell = CreateObject("WScript.Shell") > "%VBS_FILE%"
echo WshShell.Run chr(34) ^& "%SCRIPT_DIR%\clipbridge.py" ^& chr(34) ^& " --server", 0 >> "%VBS_FILE%"
echo Set WshShell = Nothing >> "%VBS_FILE%"

:: Create scheduled task
echo Creating startup task...
schtasks /create /tn "ClipBridge" /tr "\"%VBS_FILE%\"" /sc onlogon /rl highest /f

if errorlevel 1 (
    echo.
    echo WARNING: Could not create scheduled task.
    echo You may need to run this script as Administrator.
    echo.
    echo Alternative: Add this VBS file to your Startup folder:
    echo %VBS_FILE%
) else (
    echo.
    echo SUCCESS! ClipBridge will start automatically on login.
    echo.
    echo To remove: schtasks /delete /tn "ClipBridge" /f
)

echo.
echo ============================================
echo Setup complete!
echo ============================================
pause
