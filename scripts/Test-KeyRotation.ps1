[CmdletBinding()]
param()
# Live signing-key rotation drill (see scripts/live_key_rotation.py). It rotates
# the RS256 signing key of both lab realms and leaves the lab on the new keys.
# The lab has no standing Keycloak administrator, so the drill uses a temporary
# one that is deleted at the end; the identity database is backed up first.
$ErrorActionPreference = 'Stop'
$accessopsRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $accessopsRoot
. (Join-Path $PSScriptRoot 'LabCompose.ps1')
if (-not (Test-Path -LiteralPath '.local/backend.env')) { throw 'Start the lab with scripts/Start-Lab.ps1 first.' }
$accessopsReports = Join-Path $accessopsRoot 'output/connected'
New-Item -ItemType Directory -Path $accessopsReports -Force | Out-Null

Backup-IdentityDatabase -Root $accessopsRoot -Label 'key-rotation'
try {
    Start-KeycloakWithTemporaryAdmin -Label 'key-drill'
    Invoke-LabCompose -Arguments @('run', '--rm', '--no-deps', '-T', '-e', 'UPGRADE_CLIENT_ID', '-e', 'UPGRADE_CLIENT_SECRET', '-v', "${accessopsRoot}/scripts:/app/scripts:ro", '-v', "${accessopsReports}:/test-output", '-v', "${accessopsRoot}/.local/operator-logins.json:/run/test-logins.json:ro", 'backend', 'python', '/app/scripts/live_key_rotation.py', '--report', '/test-output/key-rotation.json', '--junit', '/test-output/key-rotation.xml') -Failure 'Signing-key rotation drill failed.'
} catch {
    # Leave the lab running even when a step fails; the error still stops the drill.
    try { Invoke-LabCompose -Arguments @('up', '-d', 'keycloak', 'web') }
    catch { Write-Warning 'Keycloak could not be restarted; run: docker compose -f infra/compose.yml up -d keycloak web' }
    Write-Warning "If the report does not show the temporary admin deleted, delete master-realm client $env:UPGRADE_CLIENT_ID."
    throw
} finally {
    Remove-Item Env:UPGRADE_CLIENT_ID, Env:UPGRADE_CLIENT_SECRET -ErrorAction SilentlyContinue
}
Write-Host 'Key rotation drill passed. Sanitized reports: output/connected/key-rotation.json and .xml.'
