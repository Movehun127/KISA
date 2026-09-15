"""Read startup registrations and approval records without launching entries."""
from .execution import run_ps
import json

SCRIPT = r"""
$rows = @()
foreach($hiveName in @('LocalMachine','CurrentUser')) {
 foreach($viewName in @('Registry64','Registry32')) {
  $h = [Microsoft.Win32.RegistryHive]::$hiveName
  $v = [Microsoft.Win32.RegistryView]::$viewName
  $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($h,$v)
  try {
   foreach($path in @('Software\Microsoft\Windows\CurrentVersion\Run',
                      'Software\Microsoft\Windows\CurrentVersion\RunOnce',
                      'Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run',
                      'Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32',
                      'Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder')) {
    $key=$base.OpenSubKey($path)
    if($null -eq $key) {
     $rows += [pscustomobject]@{Hive=$hiveName;View=$viewName;Path=$path;Exists=$false}
     continue
    }
    try {
     $names=@($key.GetValueNames())
     if($names.Count -eq 0){$rows += [pscustomobject]@{Hive=$hiveName;View=$viewName;Path=$path;Exists=$true;Empty=$true}}
     foreach($name in $names) {
      $value=$key.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
      if($value -is [byte[]]){$value=[BitConverter]::ToString($value)}
      $rows += [pscustomobject]@{Hive=$hiveName;View=$viewName;Path=$path;Name=$name;Value=$value;Exists=$true}
     }
    } finally {$key.Dispose()}
   }
  } finally {$base.Dispose()}
 }
}
$folders = @()
foreach($folder in @([Environment]::GetFolderPath('Startup'),[Environment]::GetFolderPath('CommonStartup'))) {
 $entries=@(Get-ChildItem -LiteralPath $folder -Force -ErrorAction Stop | Select-Object Name,FullName,Extension)
 $folders += [pscustomobject]@{Path=$folder;Entries=$entries}
}
[pscustomobject]@{Registry=$rows;StartupFolders=$folders;
 Scope='현재 실행 사용자 및 모든 사용자 Run/RunOnce와 시작 폴더, 32/64비트 및 StartupApproved 원문. 다른 사용자 프로필·UWP 시작 작업은 별도 확인.'} |
 ConvertTo-Json -Depth 8 -Compress
"""

def collect():
    data=json.loads(run_ps(SCRIPT))
    if not isinstance(data,dict) or not isinstance(data.get('Registry'),list) or not isinstance(data.get('StartupFolders'),list):
        raise RuntimeError('시작프로그램 등록 정보 조회 결과 불완전')
    return data
