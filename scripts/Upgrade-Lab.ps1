[CmdletBinding()]
param()
# One-time upgrade of an existing lab. Adds or updates only the lab-added clients
# in the workforce realm (Atlas and the read-only events reader) and operator MFA
# in the operators realm (sign-in flow, required level, one authenticator per lab
# operator). Other users, clients and sessions are untouched. New labs get all of
# it from Start-Lab.ps1.
$ErrorActionPreference = 'Stop'
$accessopsRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $accessopsRoot
$accessopsPython = Join-Path $accessopsRoot 'backend/.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath '.local/backend.env')) { throw 'No existing lab configuration. Start a new lab with scripts/Start-Lab.ps1 instead.' }
$accessopsUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
. (Join-Path $PSScriptRoot 'LabCompose.ps1')
function Protect-LocalPath([string]$Path) {
    & icacls $Path /inheritance:r /grant:r "${accessopsUser}:F" 'SYSTEM:F' /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not restrict a local credential path.' }
}

# 1. Local files: the Atlas client secret and the stored realm import.
& $accessopsPython scripts/upgrade_lab.py local
if ($LASTEXITCODE -ne 0) { throw 'Local upgrade failed.' }
& $accessopsPython scripts/upgrade_lab.py ssf
if ($LASTEXITCODE -ne 0) { throw 'Security event key generation failed.' }
& $accessopsPython scripts/upgrade_lab.py mfa
if ($LASTEXITCODE -ne 0) { throw 'Operator authenticator generation failed.' }
foreach ($accessopsSecret in @('atlas.env', 'keycloak-events.env', 'ssf-receiver.env', 'atlas-signals.env', 'ssf/signing.pem', 'operator-logins.json', 'realms/accessops-operators-realm.json')) {
    Protect-LocalPath (Join-Path $accessopsRoot ".local/$accessopsSecret")
}

# 2. Recovery point: a full identity database backup, kept under .local/backups.
Backup-IdentityDatabase -Root $accessopsRoot -Label 'upgrade'

# 3. A temporary admin service account; the realm step deletes it and proves its
#    credential is refused.
try {
    Invoke-LabCompose -Arguments @('build', 'backend', 'web')
    Start-KeycloakWithTemporaryAdmin -Label 'upgrade'
    Invoke-LabCompose -Arguments @('run', '--rm', '--no-deps', '-T', '-e', 'UPGRADE_CLIENT_ID', '-e', 'UPGRADE_CLIENT_SECRET', '-v', "${accessopsRoot}/.local/atlas.env:/run/atlas.env:ro", '-v', "${accessopsRoot}/.local/keycloak-events.env:/run/keycloak-events.env:ro", '-v', "${accessopsRoot}/.local/operator-logins.json:/run/operator-logins.json:ro", 'backend', 'python', '/app/scripts/upgrade_lab.py', 'realm')
} catch {
    # Leave the lab running even when a step fails; the error still stops the upgrade.
    try { Invoke-LabCompose -Arguments @('up', '-d', 'keycloak', 'web') }
    catch { Write-Warning 'Keycloak could not be restarted; run: docker compose -f infra/compose.yml up -d keycloak web' }
    Write-Warning "If the realm step did not report temporaryAdminRemoved, delete master-realm client $env:UPGRADE_CLIENT_ID."
    throw
} finally {
    Remove-Item Env:UPGRADE_CLIENT_ID, Env:UPGRADE_CLIENT_SECRET -ErrorAction SilentlyContinue
}

# 4. Migrate, then run the new code and start the Atlas lab app.
Invoke-LabCompose -Arguments @('run', '--rm', '--no-deps', 'backend', 'python', 'manage.py', 'migrate', '--noinput')
Invoke-LabCompose -Arguments @('up', '-d', '--wait', 'backend', 'worker', 'atlas-app')
Write-Host 'Upgrade complete: lab clients and operator MFA are current, the database is migrated and the Atlas lab app is running.'
