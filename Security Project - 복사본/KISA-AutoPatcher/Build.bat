@echo off
echo ====================================================
echo  2026 KISA Auto-Patcher C# GUI Build Utility
echo ====================================================
cd /d "%~dp0"

set "CSC_PATH=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC_PATH%" (
    echo [ERROR] csc.exe not found at: %CSC_PATH%
    exit /b 1
)

echo Compiling C# source files under Src/ into root directory...
"%CSC_PATH%" /codepage:65001 /target:winexe /out:KISA-AutoPatcher.exe /r:System.Windows.Forms.dll,System.Drawing.dll,System.dll,System.Core.dll,"C:\Windows\Microsoft.Net\assembly\GAC_MSIL\UIAutomationClient\v4.0_4.0.0.0__31bf3856ad364e35\UIAutomationClient.dll","C:\Windows\Microsoft.Net\assembly\GAC_MSIL\UIAutomationTypes\v4.0_4.0.0.0__31bf3856ad364e35\UIAutomationTypes.dll","C:\Windows\Microsoft.Net\assembly\GAC_MSIL\WindowsBase\v4.0_4.0.0.0__31bf3856ad364e35\WindowsBase.dll","C:\WINDOWS\Microsoft.Net\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0__31bf3856ad364e35\System.Management.Automation.dll" /recurse:Src\*.cs

if %ERRORLEVEL% equ 0 (
    echo ====================================================
    echo  [SUCCESS] Build Completed! KISA-AutoPatcher.exe updated.
    echo ====================================================
) else (
    echo ====================================================
    echo  [ERROR] Build Failed! Check compiler output.
    echo ====================================================
    exit /b 1
)
