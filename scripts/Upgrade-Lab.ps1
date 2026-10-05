[CmdletBinding()]
param()
# One-time upgrade of an existing lab. Adds or updates only the lab-added clients
# in the workforce realm (Atlas and the read-only events reader); users, other
# clients and sessions are untouched. New labs get them from Start-Lab.ps1.
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
foreach ($accessopsSecret in @('atlas.env', 'keycloak-events.env', 'ssf-receiver.env', 'atlas-signals.env', 'ssf/signing.pem')) {
    Protect-LocalPath (Join-Path $accessopsRoot ".local/$accessopsSecret")
}

# 2. Recovery point: a full identity database backup, kept under .local/backups.
#    Restore with pg_restore --clean into the stopped identity database if needed.
$accessopsStamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$accessopsBackups = Join-Path $accessopsRoot '.local/backups'
New-Item -ItemType Directory -Path $accessopsBackups -Force | Out-Null
& icacls $accessopsBackups /inheritance:r /grant:r "${accessopsUser}:(OI)(CI)F" 'SYSTEM:(OI)(CI)F' /Q | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not restrict the backup directory.' }
Invoke-LabCompose -Arguments @('exec', '-T', 'identity-db', 'sh', '-c', 'pg_dump -U $POSTGRES_USER -d accessops_identity -Fc -f /tmp/identity-upgrade.dump')
$accessopsBackup = ".local/backups/identity-$accessopsStamp.dump"
Invoke-LabCompose -Arguments @('cp', 'identity-db:/tmp/identity-upgrade.dump', $accessopsBackup)
Invoke-LabCompose -Arguments @('exec', '-T', 'identity-db', 'rm', '-f', '/tmp/identity-upgrade.dump')
if ((Get-Item -LiteralPath $accessopsBackup).Length -lt 1024) { throw 'Identity database backup looks empty; nothing else was changed.' }
Protect-LocalPath (Join-Path $accessopsRoot $accessopsBackup)
Write-Host "Identity database backed up to $accessopsBackup."

# 3. Temporary admin service account. Keycloak must be stopped to create it; the
#    realm step deletes it and proves its credential is refused. Values reach the
#    containers by variable name only, never on a command line.
$accessopsRandom = [byte[]]::new(36)
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($accessopsRandom)
$env:UPGRADE_CLIENT_SECRET = [Convert]::ToBase64String($accessopsRandom).TrimEnd('=').Replace('+', '-').Replace('/', '_')
$env:UPGRADE_CLIENT_ID = 'accessops-upgrade-' + $accessopsStamp.ToLowerInvariant()
try {
    Invoke-LabCompose -Arguments @('build', 'backend', 'web')
    Invoke-LabCompose -Arguments @('stop', 'keycloak')
    Invoke-LabCompose -Arguments @('run', '--rm', '--no-deps', '-T', '-e', 'UPGRADE_CLIENT_ID', '-e', 'UPGRADE_CLIENT_SECRET', '--entrypoint', '/opt/keycloak/bin/kc.sh', 'keycloak', 'bootstrap-admin', 'service', '--client-id:env', 'UPGRADE_CLIENT_ID', '--client-secret:env', 'UPGRADE_CLIENT_SECRET', '--no-prompt')
    Invoke-LabCompose -Arguments @('up', '-d', '--wait', 'keycloak', 'web')
    Invoke-LabCompose -Arguments @('run', '--rm', '--no-deps', '-T', '-e', 'UPGRADE_CLIENT_ID', '-e', 'UPGRADE_CLIENT_SECRET', '-v', "${accessopsRoot}/.local/atlas.env:/run/atlas.env:ro", '-v', "${accessopsRoot}/.local/keycloak-events.env:/run/keycloak-events.env:ro", 'backend', 'python', '/app/scripts/upgrade_lab.py', 'realm')
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
Write-Host 'Upgrade complete: lab clients are current, the database is migrated and the Atlas lab app is running.'
