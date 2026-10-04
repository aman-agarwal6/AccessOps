$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    docker compose stop dc
    if ($LASTEXITCODE -ne 0) { throw 'AD lab stop failed.' }
    Write-Output 'AD lab stopped; domain state and credentials preserved.'
} finally { Pop-Location }
