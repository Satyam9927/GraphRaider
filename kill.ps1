#Requires -Version 5.1
<# kill.ps1 - stop GraphRaider (Windows). Kills whatever listens on 8000 + 3000. #>
Set-StrictMode -Off
$ErrorActionPreference = "SilentlyContinue"

Write-Host ""
Write-Host "  GraphRaider - stopping services" -ForegroundColor Cyan

function Stop-Port {
    param([int]$Port, [string]$Label)
    $pids = netstat -ano | Select-String ":$Port\s" |
        ForEach-Object { ($_ -split '\s+')[-1] } | Where-Object { $_ -match '^\d+$' } | Select-Object -Unique
    if (-not $pids) { Write-Host "  [$Label] nothing on port $Port." -ForegroundColor DarkGray; return }
    foreach ($id in $pids) {
        try { Stop-Process -Id $id -Force; Write-Host "  [$Label] killed PID $id." -ForegroundColor Green }
        catch { Write-Host "  [$Label] PID $id already gone." -ForegroundColor DarkGray }
    }
}
Stop-Port -Port 8000 -Label "backend"
Stop-Port -Port 3000 -Label "frontend"
Write-Host "  Done." -ForegroundColor Cyan
Write-Host ""
