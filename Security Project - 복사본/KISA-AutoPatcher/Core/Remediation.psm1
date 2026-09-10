function Invoke-Remediation {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [array]$VulnerabilityResults,
        
        [string]$BackupDir = "$PSScriptRoot\..\Backups",
        
        [string]$EvidenceDir = ""
    )

    if (-not (Test-Path $BackupDir)) {
        New-Item -ItemType Directory -Path $BackupDir | Out-Null
    }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

    foreach ($result in $VulnerabilityResults) {
        if ($result.Status -like "*?묓샇*" -or $result.Status -like "*?섎룞 議곗튂*") {
            Write-Host "[$($result.ItemId)] ?곹깭媛 $($result.Status)?대?濡?議곗튂瑜?嫄대꼫?곷땲??" -ForegroundColor Green
            continue
        }

        Write-Host "[$($result.ItemId)] 痍⑥빟 ??ぉ 議곗튂瑜??쒖옉?⑸땲??.. ($($result.TechType))" -ForegroundColor Yellow
        $item = $result.ConfigItem
        $backupFile = Join-Path -Path $BackupDir -ChildPath "$($item.ItemId)_$timestamp.bak"
        $rollbackAction = $null

        try {
            switch ($item.TechType) {
                "Type_Powershell" {
                    $currentState = $result.CurrentValue
                    Set-Content -Path $backupFile -Value "PreviousState=$currentState"
                    $rollbackAction = { Write-Host "?섎룞 濡ㅻ갚 ?꾩슂" }
                    
                    Invoke-Expression $item.RemediationCommand
                }
                "Type_Registry" {
                    $regPath = $item.RegistryPath
                    $regName = $item.RegistryName
                    $backupData = @{}
                    
                    if (Test-Path $regPath) {
                        $val = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
                        if ($null -ne $val) { $backupData[$regName] = $val.$regName }
                    }
                    $backupData | ConvertTo-Json | Set-Content -Path $backupFile
                    
                    $rollbackAction = {
                        $restoreData = Get-Content -Path $backupFile | ConvertFrom-Json
                        if ($null -ne $restoreData.$regName) {
                            Set-ItemProperty -Path $regPath -Name $regName -Value $restoreData.$regName -Force
                        }
                    }

                    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
                    $regType = if ($null -ne $item.RegistryType) { $item.RegistryType } else { "DWord" }
                    Set-ItemProperty -Path $regPath -Name $regName -Value $item.SecureValue -Type $regType -Force
                }
                "Type_Secedit" {
                    $key = $item.SeceditKey
                    $secTemp = "$env:TEMP\sec_backup.inf"
                    secedit /export /cfg $secTemp /quiet
                    Copy-Item -Path $secTemp -Destination $backupFile -Force
                    
                    $rollbackAction = {
                        secedit /configure /db "$env:TEMP\sec_rollback.sdb" /cfg $backupFile /quiet
                    }

                    $content = Get-Content $secTemp
                    $newContent = $content -replace "^$key\s*=.*", "$key = $($item.SecureValue)"
                    $newContent | Set-Content $secTemp
                    secedit /configure /db "$env:TEMP\sec_apply.sdb" /cfg $secTemp /quiet
                    Remove-Item $secTemp -Force
                }
                "Type_Defender" {
                    Set-Content -Path $backupFile -Value "Signature Update Triggered"
                    Write-Host "  -> Defender ?쒕챸 ?낅뜲?댄듃瑜?諛깃렇?쇱슫?쒕줈 ?쒖옉?⑸땲??"
                    Update-MpSignature
                }
            }

            Write-Host "  -> 議곗튂 ?꾨즺 諛?諛깆뾽 ??λ맖: $($backupFile)" -ForegroundColor Green
        }
        catch {
            Write-Error "  -> 議곗튂 以??먮윭 諛쒖깮! 濡ㅻ갚???쒕룄?⑸땲?? ?먮윭: $_"
            if ($null -ne $rollbackAction) {
                try {
                    & $rollbackAction
                    Write-Host "  -> 濡ㅻ갚 ?깃났" -ForegroundColor Cyan
                }
                catch {
                    Write-Error "  -> 濡ㅻ갚 ?ㅽ뙣: $_"
                }
            }
        }
    }
}

Export-ModuleMember -Function Invoke-Remediation
