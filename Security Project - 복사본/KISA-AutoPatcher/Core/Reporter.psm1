function Invoke-Reporting {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [array]$InitialResults,

        [Parameter(Mandatory=$true)]
        [array]$FinalResults,
        
        [string]$ReportDir = "$PSScriptRoot\..\Reports",
        
        [string]$EvidenceDir = ""
    )

    if (-not (Test-Path $ReportDir)) {
        New-Item -ItemType Directory -Path $ReportDir | Out-Null
    }

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $reportFile = Join-Path -Path $ReportDir -ChildPath "Security_Patch_Report.md"

    # 1. Generate Markdown Report
    $reportContent = @"

---
## ?�도???�스??보안 ?�치 리포??**?�행 ?�시:** $timestamp
**?�행 PC:** $env:COMPUTERNAME

| ??�� 코드 | 진단 ??���?| 중요??| 조치 ???�태 | 조치 ???�태 | 최종 ?�정 |
|---|---|---|---|---|---|
"@

    for ($i = 0; $i -lt $InitialResults.Count; $i++) {
        $init = $InitialResults[$i]
        $final = $FinalResults | Where-Object { $_.ItemId -eq $init.ItemId }
        
        $isSecure = ($final.Status -like "*?�호*" -or $final.Status -like "*?�동 조치*")
        $icon = if ($isSecure) { "[O]" } else { "[X]" }
        $finalStatus = "$icon $($final.Status)"
        
        $initStatusStr = if ($init.Status -like "*?�호*" -or $init.Status -like "*?�동 조치*") { $init.Status } else { "취약 ($($init.CurrentValue))" }
        $finalStatusStr = if ($final.Status -like "*?�호*" -or $final.Status -like "*?�동 조치*") { "$($final.Status) ($($final.CurrentValue))" } else { "취약 ($($final.CurrentValue))" }

        $reportContent += "`n| $($init.ItemId) | $($init.Title) | $($init.Level) | $initStatusStr | $finalStatusStr | $finalStatus |"
    }

    $reportContent += "`n"

    Set-Content -Path $reportFile -Value $reportContent -Encoding UTF8
    Write-Host "마크?�운 보고???�데?�트 ?�료: $reportFile" -ForegroundColor Cyan

    # 2. Generate Excel Report based on Model2.xlsx template
    $excelTemplate = "c:\Users\new-s\Desktop\Security Project\Model2.xlsx"
    $excelReport = Join-Path -Path $ReportDir -ChildPath "Security_Patch_Report.xlsx"
    
    try {
        if (Test-Path $excelTemplate) {
            Copy-Item -Path $excelTemplate -Destination $excelReport -Force
            
            $excel = New-Object -ComObject Excel.Application
            $excel.Visible = $false
            $excel.DisplayAlerts = $false
            $workbook = $excel.Workbooks.Open($excelReport)
            $sheet = $workbook.Sheets.Item(1)
            
            $rowCount = $sheet.UsedRange.Rows.Count
            for ($r = 6; $r -le $rowCount; $r++) {
                $code = $sheet.Cells.Item($r, 4).Text.Trim()
                if ($code -like "W-*") {
                    $matchedItems = $FinalResults | Where-Object { $_.ItemId -eq $code -or $_.ItemId.StartsWith($code + "_") }
                    if ($matchedItems) {
                        $isSkip = $false
                        foreach ($m in $matchedItems) {
                            if ($m.ConfigItem.TechType -eq "Type_Skip") {
                                $isSkip = $true
                            }
                        }
                        if ($isSkip) {
                            continue
                        }
                        $hasManual = $false
                        $hasVuln = $false
                        $valStrings = @()
                        
                        foreach ($m in $matchedItems) {
                            if ($m.Status -like "*?�동 조치*") {
                                $hasManual = $true
                                $valStrings += "$($m.ItemId): ?�동 조치 ?�요"
                            }
                            # 만약 '?�호'가 ?�닌 취약 ?�태?�면 ?�이?�항??기록
                            elseif ($m.Status -notlike "*?�호*") {
                                $hasVuln = $true
                                $valStrings += "$($m.ItemId): 취약(?�재�?$($m.CurrentValue))"
                            }
                        }
                        
                        # 조치?��? (Column 5) 기록
                        $hasUnusedService = $false
                        $unusedServiceMsg = ""
                        foreach ($m in $matchedItems) {
                            if ($m.Status -like "*?�비??미사??") {
                                $hasUnusedService = $true
                                $unusedServiceMsg = $m.Status -replace "?�호\(", "" -replace "\)", ""
                            }
                        }

                        if ($hasUnusedService) {
                            $sheet.Cells.Item($r, 5) = "X"
                            $sheet.Cells.Item($r, 6) = $unusedServiceMsg
                        } else {
                            if ($hasVuln) {
                                $sheet.Cells.Item($r, 5) = "X"
                            } else {
                                $sheet.Cells.Item($r, 5) = "O"
                            }
                            
                            # 비고 (Column 6) 기록 - 취약?�거???�동 조치???�이?�항�?기록?�고, ?�상 조치 �??�호??빈칸 처리
                            if ($hasVuln -or $hasManual) {
                                $sheet.Cells.Item($r, 6) = [string]::Join(", ", $valStrings)
                            } else {
                                $sheet.Cells.Item($r, 6) = ""
                            }
                        }
                    }
                }
            }
            
            $workbook.Save()
            $workbook.Close($true)
            $excel.Quit()
            
            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($sheet) | Out-Null
            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($workbook) | Out-Null
            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($excel) | Out-Null
            Write-Host "?��? 보고???�성 ?�료: $excelReport" -ForegroundColor Cyan
        } else {
            Write-Warning "?��? ?�플�??�일???�습?�다: $excelTemplate"
        }
    } catch {
        Write-Warning "?��? 보고???�성 �??�류 발생: $_"
        if ($null -ne $excel) {
            try { $excel.Quit() } catch {}
        }
    }
}

Export-ModuleMember -Function Invoke-Reporting




