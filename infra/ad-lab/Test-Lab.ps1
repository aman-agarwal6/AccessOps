$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    New-Item -ItemType Directory -Path (Join-Path $PSScriptRoot 'output') -Force | Out-Null
    docker compose run --rm --no-deps probe
    if ($LASTEXITCODE -ne 0) { throw 'AD lab checks failed. Inspect the sanitized report in output.' }
} finally { Pop-Location }
