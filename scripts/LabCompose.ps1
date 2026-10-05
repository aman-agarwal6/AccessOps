# Shared by the lab scripts; dot-source it after changing to the repository root.
# Docker Compose writes progress to stderr, and Windows PowerShell 5.1 turns
# captured native stderr into a terminating error under
# $ErrorActionPreference = 'Stop'. Each step is judged by its exit code instead.
function Invoke-LabNative {
    param(
        [string]$Command,
        [string[]]$Arguments,
        [string]$Failure = 'AccessOps lab command failed.'
    )
    # Local to this function: the caller's preference is unchanged.
    $ErrorActionPreference = 'Continue'
    & $Command @Arguments 2>&1 | ForEach-Object { "$_" }
    if ($LASTEXITCODE -ne 0) { throw $Failure }
}

function Invoke-LabCompose {
    param(
        [string[]]$Arguments,
        [string]$Failure = 'AccessOps Compose operation failed.'
    )
    Invoke-LabNative -Command 'docker' -Arguments (@('compose', '-f', 'infra/compose.yml') + $Arguments) -Failure $Failure
}

# A full identity database backup under .local/backups, readable only by this
# user and SYSTEM. Restore with pg_restore --clean into the stopped database.
function Backup-IdentityDatabase {
    param([string]$Root, [string]$Label)
    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $backups = Join-Path $Root '.local/backups'
    New-Item -ItemType Directory -Path $backups -Force | Out-Null
    & icacls $backups /inheritance:r /grant:r "${user}:(OI)(CI)F" 'SYSTEM:(OI)(CI)F' /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not restrict the backup directory.' }
    Invoke-LabCompose -Arguments @('exec', '-T', 'identity-db', 'sh', '-c', 'pg_dump -U $POSTGRES_USER -d accessops_identity -Fc -f /tmp/identity-backup.dump') | Out-Host
    $file = ".local/backups/identity-$Label-$stamp.dump"
    Invoke-LabCompose -Arguments @('cp', 'identity-db:/tmp/identity-backup.dump', $file) | Out-Host
    Invoke-LabCompose -Arguments @('exec', '-T', 'identity-db', 'rm', '-f', '/tmp/identity-backup.dump') | Out-Host
    if ((Get-Item -LiteralPath (Join-Path $Root $file)).Length -lt 1024) { throw 'Identity database backup looks empty; nothing else was changed.' }
    & icacls (Join-Path $Root $file) /inheritance:r /grant:r "${user}:F" 'SYSTEM:F' /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not restrict the identity database backup.' }
    Write-Host "Identity database backed up to $file."
}

# The lab has no standing Keycloak administrator. This creates a temporary admin
# service account, which needs Keycloak stopped, then starts Keycloak again. Its
# ID and secret reach containers by variable name only (UPGRADE_CLIENT_ID and
# UPGRADE_CLIENT_SECRET), never on a command line; scripts/lab_admin.py deletes
# the account and proves its credential is refused. Callers remove the variables.
function Start-KeycloakWithTemporaryAdmin {
    param([string]$Label)
    $random = [byte[]]::new(36)
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($random)
    $env:UPGRADE_CLIENT_SECRET = [Convert]::ToBase64String($random).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    $env:UPGRADE_CLIENT_ID = "accessops-$Label-" + (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ').ToLowerInvariant()
    Invoke-LabCompose -Arguments @('stop', 'keycloak') | Out-Host
    Invoke-LabCompose -Arguments @('run', '--rm', '--no-deps', '-T', '-e', 'UPGRADE_CLIENT_ID', '-e', 'UPGRADE_CLIENT_SECRET', '--entrypoint', '/opt/keycloak/bin/kc.sh', 'keycloak', 'bootstrap-admin', 'service', '--client-id:env', 'UPGRADE_CLIENT_ID', '--client-secret:env', 'UPGRADE_CLIENT_SECRET', '--no-prompt') | Out-Host
    Invoke-LabCompose -Arguments @('up', '-d', '--wait', 'keycloak', 'web') | Out-Host
}
