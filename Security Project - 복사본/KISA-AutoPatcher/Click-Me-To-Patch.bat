@echo off
:: This batch file runs the PowerShell script with Administrator privileges and bypasses the execution policy.
echo ====================================================
echo Requesting Administrator privileges for KISA Auto-Patcher...
echo ====================================================

:: Check for Administrator privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    goto :run_script
) else (
    echo No Administrator privileges found. Restarting with elevated privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:run_script
cd /d "%~dp0"
echo Starting PowerShell script...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File ".\Run-Patcher.ps1"
echo.
pause
