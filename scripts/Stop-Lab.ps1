$ErrorActionPreference = 'Stop'
$accessopsRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $accessopsRoot
& docker compose -f infra/compose.yml stop
if ($LASTEXITCODE -ne 0) { throw 'Could not stop AccessOps services.' }
Write-Host 'AccessOps stopped; databases, credentials, and evidence were preserved.'
