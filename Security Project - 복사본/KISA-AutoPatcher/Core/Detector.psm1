function Get-VulnerabilityStatus {
    [CmdletBinding()]
    param (
        [string]$ConfigPath = "$PSScriptRoot\..\Config\KisaCriteria.json"
    )

    if (-not (Test-Path $ConfigPath)) {
        Write-Error "Config file not found: $ConfigPath"
        return
    }

    $criteriaList = @()
    if (Test-Path $ConfigPath -PathType Container) {
        $files = Get-ChildItem -Path $ConfigPath -Filter *.json | Sort-Object Name
        foreach ($file in $files) {
            $jsonObj = Get-Content $file.FullName -Encoding UTF8 -Raw | ConvertFrom-Json
            $criteriaList += $jsonObj
        }
    } else {
        $criteriaList = Get-Content $ConfigPath -Encoding UTF8 -Raw | ConvertFrom-Json
    }
    $results = @()
    
    # Secedit 캐싱???�한 ?�일
    $seceditTemp = "$env:TEMP\secedit_dump.inf"
    $seceditLoaded = $false

    foreach ($item in $criteriaList) {
        $status = "?�호"
        $currentValue = $null

        try {
            switch ($item.TechType) {
                "Type_Skip" {
                    $status = "?�동 조치($($item.Description))"
                    if ($null -ne $item.CheckCommand -and $item.CheckCommand -ne "") {
                        try {
                            $currentValue = Invoke-Expression $item.CheckCommand
                        } catch {
                            $currentValue = "Error executing check"
                        }
                    } else {
                        $currentValue = "N/A"
                    }
                }
                "Type_Powershell" {
                    $currentValue = Invoke-Expression $item.CheckCommand
                    if ([string]$currentValue -ne $item.SecureValue) {
                        $status = "취약"
                    }
                }
                "Type_Registry" {
                    $regPath = $item.RegistryPath
                    $regName = $item.RegistryName
                    
                    if (Test-Path $regPath) {
                        $val = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
                        if ($null -ne $val) {
                            $currentValue = $val.$regName
                        }
                    }
                    
                    if ([string]$currentValue -ne $item.SecureValue) {
                        $status = "취약"
                    }
                    if ($null -eq $currentValue -and $item.SecureValue -ne "") {
                        $status = "취약"
                        $currentValue = "Not Found"
                    }
                }
                "Type_Secedit" {
                    if (-not $seceditLoaded) {
                        secedit /export /cfg $seceditTemp /quiet
                        $seceditLoaded = $true
                    }
                    $key = $item.SeceditKey
                    $match = Select-String -Path $seceditTemp -Pattern "^$key\s*=\s*(.*)$" -Quiet
                    if ($match) {
                        $line = (Select-String -Path $seceditTemp -Pattern "^$key\s*=\s*(.*)$").Matches.Groups[1].Value.Trim()
                        $currentValue = $line
                    } else {
                        $currentValue = "Not Found"
                    }
                    
                    # W-04 계정 ?�금 ?�계�? 5 ?�하
                    if ($key -eq "LockoutBadCount") {
                        if ([int]$currentValue -gt [int]$item.SecureValue -or [int]$currentValue -eq 0) {
                            $status = "취약"
                        }
                    } else {
                        if ([string]$currentValue -ne $item.SecureValue) {
                            $status = "취약"
                        }
                    }
                }
                "Type_Defender" {
                    $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
                    if ($null -ne $mp) {
                        $days = (Get-Date) - $mp.AntivirusSignatureLastUpdated
                        if ($days.Days -gt 7) {
                            $status = "취약"
                            $currentValue = "Outdated ($($days.Days) days)"
                        } else {
                            $currentValue = "UpToDate"
                        }
                    } else {
                        $status = "취약"
                        $currentValue = "Defender Not Found"
                    }
                }
            }

            $results += [PSCustomObject]@{
                ItemId      = $item.ItemId
                Title       = $item.Title
                Level       = $item.Level
                TechType    = $item.TechType
                Status      = $status
                CurrentValue= $currentValue
                SecureValue = $item.SecureValue
                ConfigItem  = $item
            }
        }
        catch {
            Write-Warning "Failed to check $($item.ItemId): $_"
            $results += [PSCustomObject]@{
                ItemId      = $item.ItemId
                Title       = $item.Title
                Level       = $item.Level
                TechType    = $item.TechType
                Status      = "?�러"
                CurrentValue= "Error"
                SecureValue = $item.SecureValue
                ConfigItem  = $item
            }
        }
    }

    if (Test-Path $seceditTemp) { Remove-Item $seceditTemp -Force }

    return $results
}

Export-ModuleMember -Function Get-VulnerabilityStatus





