$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
python -m PyInstaller --clean --noconfirm --onefile --noconsole --name KISA-AutoPatcher --add-data "config;config" --collect-all customtkinter --collect-all uiautomation main.py
if ($LASTEXITCODE -ne 0) { throw 'EXE build failed' }
Write-Host 'Build complete: dist\KISA-AutoPatcher.exe (policies included)'
