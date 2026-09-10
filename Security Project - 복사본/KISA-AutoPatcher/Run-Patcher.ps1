#Requires -RunAsAdministrator

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " KISA Windows Auto-Patcher Pipeline Started  " -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

$ScriptDir = $PSScriptRoot

# 모듈 로드
Import-Module "$ScriptDir\Core\Detector.psm1" -Force
Import-Module "$ScriptDir\Core\Reporter.psm1" -Force
Import-Module "$ScriptDir\Core\Remediation.psm1" -Force

# 실행 모드 선택 UI
Write-Host "`n실행 모드를 선택해 주십시오:" -ForegroundColor White
Write-Host " [1] 전체 자동 적용 모드 (Full Auto Mode)" -ForegroundColor Green
Write-Host "     - 43~44개 전체 항목을 중단 없이 원스톱으로 조치하고 리포트를 생성합니다."
Write-Host " [2] 단계별 순차 적용 모드 (Interactive Step Mode)" -ForegroundColor Yellow
Write-Host "     - 항목별 조치 완료 후 설정 창(UI)을 띄워 확인하고 스크린샷 증빙을 수집합니다."

$choice = ""
while ($choice -notmatch '^[12]$') {
    $choice = Read-Host "선택 (1 또는 2)"
    $choice = $choice.Trim()
}

$isInteractive = ($choice -eq "2")

Write-Host "`n[단계 1] 취약점 검출 (Detection)" -ForegroundColor Yellow
$InitialResults = Get-VulnerabilityStatus -ConfigPath "$ScriptDir\Config\Policies"
foreach ($res in $InitialResults) {
    $color = if ($res.Status -eq "양호" -or $res.Status -like "*수동 조치*") { "Green" } else { "Red" }
    Write-Host " - $($res.ItemId): $($res.Status) (현재: $($res.CurrentValue))" -ForegroundColor $color
}

# 백업 디렉터리 및 증빙 디렉터리 준비
$BackupDir = "$ScriptDir\Backups"
$EvidenceDir = "$ScriptDir\Evidence"
if (-not (Test-Path $BackupDir)) { New-Item -ItemType Directory -Path $BackupDir | Out-Null }
if (-not (Test-Path $EvidenceDir)) { New-Item -ItemType Directory -Path $EvidenceDir | Out-Null }
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

Write-Host "`n[단계 2] 취약점 조치 (Remediation & Backup)" -ForegroundColor Yellow

$PostResults = @()

foreach ($result in $InitialResults) {
    $itemId = $result.ItemId
    $screenPng = "$EvidenceDir\${itemId}_Screen_Proof.png"
    
    # 조치 대상이 아닌 경우 (양호 또는 수동 조치)
    if ($result.Status -like "*양호*" -or $result.Status -like "*수동 조치*") {
        Write-Host "[$itemId] 상태가 $($result.Status)이므로 조치를 건너뜁니다." -ForegroundColor Green
    } else {
        Write-Host "[$itemId] 취약 항목 조치를 시작합니다... ($($result.TechType))" -ForegroundColor Yellow
        # 개별 항목 조치 수행
        Invoke-Remediation -VulnerabilityResults @($result) -BackupDir $BackupDir -EvidenceDir $EvidenceDir
        
        # 조치 결과 확인을 위해 재검출 수행
        $currentCheck = Get-VulnerabilityStatus -ConfigPath "$ScriptDir\Config\Policies" | Where-Object { $_.ItemId -eq $itemId }
        $result = $currentCheck
    }
    $PostResults += $result
    
    # 인터랙티브 모드인 경우 윈도우 UI 팝업 및 대기 (양호/조치/수동 모든 항목 대상)
    if ($isInteractive) {
        $uiProcess = $null
        $title = $result.Title
        $desc = $result.ConfigItem.Description
        $cat = $result.ConfigItem.Category
        $tech = $result.TechType

        # 알고리즘 기반 UI 창 팝업 결정 분기
        if ($tech -eq "Type_Registry" -or ($null -ne $result.ConfigItem.RegistryPath)) {
            Write-Host "  -> 레지스트리 편집기(regedit.exe)를 해당 경로로 포커싱하여 엽니다..." -ForegroundColor Cyan
            if ($null -ne $result.ConfigItem.RegistryPath) {
                $clipPath = $result.ConfigItem.RegistryPath -replace 'HKLM:\\', 'HKEY_LOCAL_MACHINE\' -replace 'HKCU:\\', 'HKEY_CURRENT_USER\'
                
                # 레지스트리 편집기가 켜질 때 해당 경로를 바로 열 수 있도록 LastKey 설정
                try {
                    $regKeyPath = "Software\Microsoft\Windows\CurrentVersion\Applets\Regedit"
                    $regKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($regKeyPath, $true)
                    if ($null -ne $regKey) {
                        # HKLM:\ 또는 HKCU:\ 형식의 경로를 레지스트리 표준 경로 명칭으로 매핑하여 강제 주입
                        $fullRegPath = "Computer\" + $clipPath
                        $regKey.SetValue("LastKey", $fullRegPath)
                        $regKey.Close()
                    }
                } catch {
                    # LastKey 설정 실패 시 건너뜀
                }

                try {
                    Add-Type -AssemblyName System.Windows.Forms
                    [System.Windows.Forms.Clipboard]::SetText($clipPath)
                    Write-Host "  [TIP] 레지스트리 경로가 클립보드에 복사되었습니다: $clipPath" -ForegroundColor Gray
                } catch {
                    try {
                        Set-Clipboard -Value $clipPath -ErrorAction SilentlyContinue
                        Write-Host "  [TIP] 레지스트리 경로가 클립보드에 복사되었습니다: $clipPath" -ForegroundColor Gray
                    } catch {
                        Write-Host "  [안내] 클립보드 복사 실패. 경로를 수동으로 복사하세요: $clipPath" -ForegroundColor DarkGray
                    }
                }
            }
            try {
                # regedit의 세부 경로 적용을 유도하기 위해 이전 실행 중인 프로세스를 종료하고 새로 띄움
                Stop-Process -Name "regedit" -Force -ErrorAction SilentlyContinue | Out-Null
                Start-Sleep -Milliseconds 200
                $uiProcess = Start-Process "regedit.exe" -PassThru
            } catch {
                Write-Warning "regedit.exe 실행에 실패했습니다. 수동으로 실행해 주세요."
            }
        }
        elseif ($tech -eq "Type_Secedit" -or $title -like "*비밀번호*" -or $title -like "*암호*" -or $title -like "*로그온*" -or $title -like "*감사*" -or $title -like "*잠금*") {
            Write-Host "  -> 로컬 보안 정책 창(secpol.msc)을 엽니다..." -ForegroundColor Cyan
            $uiProcess = Start-Process "secpol.msc" -PassThru
        }
        elseif ($title -like "*서비스*" -or $desc -like "*서비스*" -or $desc -like "*구동*") {
            Write-Host "  -> 서비스 관리 창(services.msc)을 엽니다..." -ForegroundColor Cyan
            $uiProcess = Start-Process "services.msc" -PassThru
        }
        elseif ($title -like "*계정*" -or $title -like "*그룹*" -or $title -like "*사용자*") {
            Write-Host "  -> 로컬 사용자 및 그룹 관리 창(lusrmgr.msc)을 엽니다..." -ForegroundColor Cyan
            
            # W-06, W-11, W-14 등에 대응하여 콘솔에 실제 로컬 그룹 구성원 정보를 직접 출력해 줍니다.
            if ($title -like "*관리자*" -or $desc -like "*Administrators*") {
                Write-Host "`n  [실시간 멤버 쿼리 결과: Administrators 그룹]" -ForegroundColor Yellow
                net localgroup Administrators | Out-String | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
            }
            elseif ($title -like "*로그온 허용*" -or $desc -like "*Users*") {
                Write-Host "`n  [실시간 멤버 쿼리 결과: Users 그룹]" -ForegroundColor Yellow
                net localgroup Users | Out-String | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
            }
            elseif ($title -like "*원격터미널*" -or $desc -like "*Remote Desktop Users*") {
                Write-Host "`n  [실시간 멤버 쿼리 결과: Remote Desktop Users 그룹]" -ForegroundColor Yellow
                net localgroup "Remote Desktop Users" 2>$null | Out-String | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
            }

            $uiProcess = Start-Process "lusrmgr.msc" -PassThru
        }
        elseif ($tech -eq "Type_Defender" -or $title -like "*백신*" -or $title -like "*Defender*") {
            Write-Host "  -> Windows 보안 센터를 엽니다..." -ForegroundColor Cyan
            try {
                # UWP 앱 프로토콜(windowsdefender:)은 explorer.exe를 매개체로 띄우는 것이 가장 안전하고 호환성이 높습니다.
                # 프로세스 추적을 위해 SecurityHealthSystray.exe도 같이 감지할 수 있지만, 프로토콜 기동 자체는 explorer를 사용합니다.
                $uiProcess = Start-Process "explorer.exe" -ArgumentList "windowsdefender:" -PassThru
            } catch {
                Write-Warning "Windows 보안 센터 실행에 실패했습니다. 수동으로 실행해 주세요."
            }
        }
        elseif ($title -like "*공유*" -or $title -like "*디렉터리*" -or $title -like "*파일*" -or $title -like "*권한*") {
            # Type_ACL 및 파일 속성 보안 탭 매핑
            Write-Host "  -> 시스템 구성 또는 파일 탐색기 속성 창을 유도합니다..." -ForegroundColor Cyan
            $uiProcess = Start-Process "explorer.exe" -ArgumentList "/select,`"$env:SystemRoot\System32\Config\SAM`"" -PassThru
        }
        else {
            # 기본 폴백: 로컬 그룹 정책 편집기(gpedit.msc)
            Write-Host "  -> 로컬 그룹 정책 편집기(gpedit.msc)를 엽니다..." -ForegroundColor Cyan
            $uiProcess = Start-Process "gpedit.msc" -PassThru
        }
        
        Write-Host "`n========================================================" -ForegroundColor Magenta
        Write-Host " [검증 항목] $itemId : $title" -ForegroundColor Yellow
        Write-Host " [설명 요약] $desc" -ForegroundColor White
        Write-Host " [현재 상태] $($result.Status)" -ForegroundColor Cyan
        Write-Host "========================================================" -ForegroundColor Magenta
        Write-Host " 조치 상태를 화면에서 확인하신 후 [Enter]를 누르면 증빙 캡처 후 다음 단계로 진행합니다..." -ForegroundColor Magenta
        Read-Host
        
        # 스크린샷 캡처 (Enter 누른 시점)
        Take-Screenshot -Path $screenPng
        
        # 실행했던 UI 프로세스 정리 (explorer.exe 등 백그라운드 셸을 제외하고 안전하게 종료 시도)
        if ($null -ne $uiProcess -and $uiProcess.ProcessName -ne "explorer") {
            try {
                $uiProcess | Stop-Process -Force -ErrorAction SilentlyContinue
            } catch {}
        }
    } else {
        # 전체 자동 모드인 경우 건너뛴 항목이 아니면 루프 내에서 기본 화면 캡처 수행
        if (-not (Test-Path $screenPng)) {
            Take-Screenshot -Path $screenPng
        }
    }
}

Write-Host "`n[단계 3] 조치 후 재검증 및 보고 (Reporting)" -ForegroundColor Yellow
$FinalResults = Get-VulnerabilityStatus -ConfigPath "$ScriptDir\Config\Policies"
Invoke-Reporting -InitialResults $InitialResults -FinalResults $FinalResults -ReportDir "$ScriptDir\Reports" -EvidenceDir $EvidenceDir

Write-Host "`n=============================================" -ForegroundColor Cyan
Write-Host " 파이프라인 실행이 완료되었습니다.           " -ForegroundColor Cyan
Write-Host " 리포트를 확인하세요: Reports/Security_Patch_Report.md" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

