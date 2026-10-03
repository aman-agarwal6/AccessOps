#Requires -RunAsAdministrator
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$accessopsHosts = Join-Path $env:SystemRoot 'System32/drivers/etc/hosts'
$accessopsExisting = Get-Content -LiteralPath $accessopsHosts -Raw
$accessopsNames = @('accessops.test', 'id.accessops.test')
foreach ($accessopsName in $accessopsNames) {
    $accessopsEscaped = [regex]::Escape($accessopsName)
    $accessopsMatches = $accessopsExisting -split '\r?\n' | Where-Object { ($_ -split '#')[0] -match "\s$accessopsEscaped(?:\s|$)" }
    if ($accessopsMatches) {
        if ($accessopsMatches | Where-Object { $_ -notmatch '^\s*127\.0\.0\.1\s' }) { throw "An existing hosts entry for $accessopsName is not loopback; no changes made." }
    }
}
foreach ($accessopsName in $accessopsNames) {
    $accessopsEscaped = [regex]::Escape($accessopsName)
    if (-not (($accessopsExisting -split '\r?\n') | Where-Object { ($_ -split '#')[0] -match "\s$accessopsEscaped(?:\s|$)" })) {
        Add-Content -LiteralPath $accessopsHosts -Value "`r`n127.0.0.1 $accessopsName # AccessOps local lab" -Encoding ascii
    }
}
Write-Host 'AccessOps lab hostnames resolve to loopback. No other hosts entries were changed.'
