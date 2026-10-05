[CmdletBinding()]
param([switch]$TrustLocalCA, [switch]$SkipBuild)
$ErrorActionPreference = 'Stop'
$accessopsRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $accessopsRoot
$accessopsPython = Join-Path $accessopsRoot 'backend/.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $accessopsPython)) { throw 'Create backend/.venv and install backend/requirements.lock with --require-hashes first (Python 3.13 recommended).' }
# Protect new credentials before generation. Keep ACL maintenance scoped to
# credential paths so unrelated local tools/test scratch directories are intact.
$accessopsLocal = Join-Path $accessopsRoot '.local'
New-Item -ItemType Directory -Path $accessopsLocal -Force | Out-Null
if ((Get-Item -LiteralPath $accessopsLocal -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'The local credential directory must not be a symlink or junction.' }
$accessopsUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
& icacls $accessopsLocal /inheritance:r /grant:r "${accessopsUser}:(OI)(CI)F" 'SYSTEM:(OI)(CI)F' /Q | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not restrict the local credential directory.' }
if (-not (Test-Path -LiteralPath '.local/backend.env')) {
    & $accessopsPython scripts/generate_local.py
    if ($LASTEXITCODE -ne 0) { throw 'Local configuration generation failed.' }
}
# Labs created before HR intake get its signing secret; existing secrets are kept.
& $accessopsPython scripts/upgrade_lab.py hr
if ($LASTEXITCODE -ne 0) { throw 'HR intake secret generation failed.' }
# Windows: remove inherited broad ACLs from this application's credential directory.
# The current user and SYSTEM retain access; Docker Desktop file sharing uses this user.
foreach ($accessopsSecretPath in @('tls', 'executor', 'realms', 'backend.env', 'app-db.env', 'identity-db.env', 'keycloak.env', 'policy.env', 'policy-runtime.env', 'operator-logins.json', 'atlas.env', 'hr-intake.env', 'backups')) {
    $accessopsTarget = Join-Path $accessopsLocal $accessopsSecretPath
    if (Test-Path -LiteralPath $accessopsTarget) {
        $accessopsItem = Get-Item -LiteralPath $accessopsTarget -Force
        if ($accessopsItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Credential paths must not be symlinks or junctions.' }
        if ($accessopsItem.PSIsContainer) {
            & icacls $accessopsTarget /inheritance:r /grant:r "${accessopsUser}:(OI)(CI)F" 'SYSTEM:(OI)(CI)F' /Q | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Could not restrict a local credential directory.' }
            $accessopsFiles = @(Get-ChildItem -LiteralPath $accessopsTarget -Recurse -File -Force)
        } else {
            $accessopsFiles = @($accessopsItem)
        }
        foreach ($accessopsFile in $accessopsFiles) {
            if ($accessopsFile.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Credential files must not be symlinks or junctions.' }
            # Files need direct rights; (OI)/(CI) inheritance flags apply only
            # to directories and can otherwise leave an empty file DACL.
            & icacls $accessopsFile.FullName /inheritance:r /grant:r "${accessopsUser}:F" 'SYSTEM:F' /Q | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Could not restrict a local credential file.' }
        }
    }
}
& $accessopsPython scripts/build_policy.py
if ($LASTEXITCODE -ne 0) { throw 'Policy bundle generation failed.' }
# Reuse the selected Docker context and installed plugins. No credential contents are read.
$accessopsDocker = @('compose', '-f', 'infra/compose.yml')
function Invoke-LabCompose {
    param([string[]]$Arguments)
    & docker @accessopsDocker @Arguments
    if ($LASTEXITCODE -ne 0) { throw 'AccessOps Compose operation failed.' }
}
if (-not $SkipBuild) { Invoke-LabCompose -Arguments @('build') }
# The edge generates the CA before clients start. Only its public certificate is exported.
Invoke-LabCompose -Arguments @('up', '-d', 'web')
$accessopsCopied = $false
# Compose reports copy progress on stderr. Windows PowerShell 5.1 turns redirected
# native stderr into an error record, so rely on the exit code inside this loop.
$accessopsPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    for ($accessopsAttempt = 0; $accessopsAttempt -lt 20; $accessopsAttempt++) {
        & docker @accessopsDocker cp web:/data/caddy/pki/authorities/local/root.crt .local/tls/root.crt 2>$null
        if ($LASTEXITCODE -eq 0) { $accessopsCopied = $true; break }
        Start-Sleep -Seconds 1
    }
} finally { $ErrorActionPreference = $accessopsPreference }
if (-not $accessopsCopied) { throw 'Public local CA certificate was not generated.' }
if ($TrustLocalCA) {
    # Explicit switch: trust applies only to the current Windows user, never LocalMachine.
    $accessopsCertificate = Import-Certificate -FilePath (Join-Path $accessopsRoot '.local/tls/root.crt') -CertStoreLocation Cert:\CurrentUser\Root
    $accessopsCertificate.Thumbprint | Set-Content -LiteralPath '.local/tls/trusted-thumbprint.txt'
    Write-Host 'Trusted the AccessOps local CA for the current Windows user.'
}
Invoke-LabCompose -Arguments @('up', '-d', '--wait', 'app-db', 'identity-db', 'keycloak', 'opa', 'policy')
Invoke-LabCompose -Arguments @('restart', 'opa', 'policy')
Invoke-LabCompose -Arguments @('run', '--rm', '--no-deps', 'backend', 'python', 'manage.py', 'migrate', '--noinput')
Invoke-LabCompose -Arguments @('run', '--rm', '--no-deps', 'backend', 'python', 'manage.py', 'seed_demo')
Invoke-LabCompose -Arguments @('up', '-d', '--wait', 'backend', 'worker')
# The Atlas lab app gives offboarding a real application session to end.
if (Test-Path -LiteralPath '.local/atlas.env') {
    Invoke-LabCompose -Arguments @('up', '-d', '--wait', 'atlas-app')
} else {
    Write-Host 'This lab predates session revocation. Run scripts/Upgrade-Lab.ps1 once to add the Atlas lab app.'
}
Write-Host 'AccessOps services are ready at https://accessops.test:8443.'
Write-Host 'Windows hosts must resolve accessops.test and id.accessops.test to 127.0.0.1. See scripts/Configure-Hosts.ps1.'
Write-Host 'Credentials are local-only in .local/operator-logins.json. Do not share or commit that file.'
if (-not $TrustLocalCA) { Write-Host 'Browser trust is not installed. Re-run with -TrustLocalCA after reviewing the local CA.' }
