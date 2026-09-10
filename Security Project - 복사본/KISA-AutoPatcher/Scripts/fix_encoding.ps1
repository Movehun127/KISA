$files = Get-ChildItem -Path "$PSScriptRoot\..\Core\*", "$PSScriptRoot\..\Config\*", "$PSScriptRoot\..\Src\*" -Include *.ps1, *.psm1, *.json, *.cs | ForEach-Object {
    $path = $_.FullName
    $content = [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8)
    # UTF-8 with BOM 강제 변환
    [System.IO.File]::WriteAllText($path, $content, [System.Text.Encoding]::UTF8)
    Write-Host "Converted: $path"
}
