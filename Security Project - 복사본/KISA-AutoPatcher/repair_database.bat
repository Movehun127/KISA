@echo off
echo ====================================================
echo  Windows Security Database (secedit.sdb) Repair Tool
echo ====================================================
echo.
echo Please run this batch file as Administrator.
echo.
pause

echo 1. Stopping Cryptographic Services...
net stop cryptsvc /y

echo 2. Taking ownership of secedit.sdb...
takeown /f C:\Windows\security\database\secedit.sdb
icacls C:\Windows\security\database\secedit.sdb /grant administrators:F

echo 3. Attempting to repair database in-place (esentutl)...
esentutl /p C:\Windows\security\database\secedit.sdb /o

echo 4. Reconstructing secedit.sdb...
secedit /configure /db C:\Windows\security\database\secedit.sdb /cfg C:\Windows\inf\defltbase.inf /overwrite

echo 5. Scheduling deletion on next reboot if still locked...
powershell -Command "$path = 'HKLM:\System\CurrentControlSet\Control\Session Manager'; $name = 'PendingFileRenameOperations'; $existing = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue; $newVal = [string[]]('\??\C:\Windows\security\database\secedit.sdb', ''); if ($existing -and $existing.$name) { $newVal = [string[]]($existing.$name + $newVal) }; Set-ItemProperty -Path $path -Name $name -Value $newVal -Force"
echo Secedit.sdb has been scheduled for deletion on next reboot.

echo 6. Restarting Cryptographic Services...
net start cryptsvc

echo.
echo ====================================================
echo  Repair Complete! If the error persists, please REBOOT your PC.
echo ====================================================
pause
