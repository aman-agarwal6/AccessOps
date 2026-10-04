param([switch]$SkipBuild)
$ErrorActionPreference = 'Stop'
$labRoot = $PSScriptRoot
# Never reuse an existing Compose project from a different checkout with newly
# generated credentials. The integration wrapper accepts its explicit LabRoot.
$labExistingIds = @(docker ps -a --filter 'label=com.docker.compose.project=accessops-adlab' --filter 'label=com.docker.compose.service=dc' --format '{{.ID}}')
if ($LASTEXITCODE -ne 0) { throw 'Unable to inspect existing directory project origin.' }
foreach ($labExistingId in $labExistingIds) {
    $labOrigin = (docker inspect --format '{{json .Config.Labels}}' $labExistingId | ConvertFrom-Json).'com.docker.compose.project.working_dir'
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($labOrigin) -or [IO.Path]::GetFullPath($labOrigin.Trim()) -ne [IO.Path]::GetFullPath($labRoot)) {
        throw 'Existing accessops-adlab belongs to another source path. Use scripts/Prepare-ADLab.ps1 with its explicit -LabRoot; state was preserved.'
    }
}
$privateRoot = Join-Path $labRoot '.local'
$reportRoot = Join-Path $labRoot 'output'
New-Item -ItemType Directory -Path $privateRoot,$reportRoot -Force | Out-Null
$currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$systemIdentity = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-18'
function Protect-LabPath([string]$Path,[bool]$Directory) {
    $permissions = if ($Directory) { '(OI)(CI)F' } else { 'F' }
    & icacls.exe $Path '/inheritance:r' '/grant:r' "*$($currentIdentity.Value):$permissions" "*$($systemIdentity.Value):$permissions" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Unable to protect lab credentials.' }
    $allowed = @($currentIdentity.Value,$systemIdentity.Value)
    foreach ($rule in @((Get-Acl -LiteralPath $Path).Access)) {
        $ruleSid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        if ($ruleSid -notin $allowed) {
            & icacls.exe $Path '/remove:g' "*$ruleSid" | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Unable to remove an unexpected credential access rule.' }
        }
    }
    $verifiedAcl = Get-Acl -LiteralPath $Path
    if (-not $verifiedAcl.AreAccessRulesProtected -or @($verifiedAcl.Access | Where-Object {
        $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -notin $allowed
    }).Count -ne 0) { throw 'Private credential ACL verification failed.' }
}
Protect-LabPath $privateRoot $true
foreach ($passwordName in @('administrator-password.txt','mara-password.txt')) {
  $passwordFile = Join-Path $privateRoot $passwordName
  if (-not (Test-Path -LiteralPath $passwordFile)) {
    $randomBytes = New-Object byte[] 32
    $randomGenerator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $randomGenerator.GetBytes($randomBytes) } finally { $randomGenerator.Dispose() }
    $generatedPassword = 'Aa1!' + [Convert]::ToBase64String($randomBytes)
    [System.IO.File]::WriteAllText($passwordFile,$generatedPassword,(New-Object System.Text.UTF8Encoding $false))
    $generatedPassword = $null
  }
  Protect-LabPath $passwordFile $false
}
Push-Location $labRoot
try {
    if (-not $SkipBuild) {
        docker compose build --quiet
        if ($LASTEXITCODE -ne 0) { throw 'AD lab image build failed.' }
    }
    docker compose up -d --wait --wait-timeout 240 dc
    if ($LASTEXITCODE -ne 0) { throw 'AD lab did not become healthy. Existing domain state is preserved.' }
    Write-Output 'ADLAB.TEST is running on its isolated Docker network. No host ports are published.'
} finally { Pop-Location }
