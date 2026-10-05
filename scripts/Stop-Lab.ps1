$ErrorActionPreference = 'Stop'
$accessopsRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $accessopsRoot
. (Join-Path $PSScriptRoot 'LabCompose.ps1')
Invoke-LabCompose -Arguments @('stop') -Failure 'Could not stop AccessOps services.'
Write-Host 'AccessOps stopped; databases, credentials, and evidence were preserved.'
