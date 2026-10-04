param([string]$LabRoot = (Join-Path $PSScriptRoot '../infra/ad-lab'), [switch]$PassThru)
$ErrorActionPreference = 'Stop'
# Container stdin must be UTF-8 without a BOM. Windows PowerShell 5.1 writes native
# stdin with the console input encoding, so pin it only for the duration of a pipe.
function Invoke-ContainerInput([string]$Text, [string[]]$Arguments) {
    $previousInput, $previousOutput = [Console]::InputEncoding, $OutputEncoding
    [Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
    $OutputEncoding = [Text.UTF8Encoding]::new($false)
    try { $Text | docker @Arguments } finally { [Console]::InputEncoding = $previousInput; $OutputEncoding = $previousOutput }
}
$accessopsRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$adLabRoot = (Resolve-Path -LiteralPath $LabRoot).Path
$adCompose = Join-Path $adLabRoot 'compose.yml'
if (-not (Test-Path -LiteralPath $adCompose)) { throw 'Explicit directory lab source is missing.' }

# Check origin before invoking startup or generating any new credential file.
$adExistingIds = @(docker ps -a --filter 'label=com.docker.compose.project=accessops-adlab' --filter 'label=com.docker.compose.service=dc' --format '{{.ID}}')
if ($LASTEXITCODE -ne 0) { throw 'Unable to inspect the isolated directory project.' }
foreach ($adExistingId in $adExistingIds) {
    $adOrigin = (docker inspect --format '{{json .Config.Labels}}' $adExistingId | ConvertFrom-Json).'com.docker.compose.project.working_dir'
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($adOrigin)) { throw 'Existing lab origin is unknown; preserve it for review.' }
    if ([IO.Path]::GetFullPath($adOrigin.Trim()) -ne $adLabRoot) {
        throw 'An existing accessops-adlab uses another source directory. Re-run with its explicit -LabRoot; no startup or credentials were changed.'
    }
}
if ($adExistingIds.Count -eq 0) { & (Join-Path $adLabRoot 'Start-Lab.ps1') }
$adDcId = (docker compose -f $adCompose ps -q dc).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($adDcId)) { throw 'Directory DC is not running; start the explicit lab first.' }
$adHealth = docker inspect --format '{{.State.Health.Status}}' $adDcId
if ($LASTEXITCODE -ne 0 -or $adHealth.Trim() -ne 'healthy') { throw 'Directory DC is not healthy; no fixture changes were made.' }

$adPrivate = Join-Path $accessopsRoot '.local/ad'
function Assert-ADPath([string]$Path) {
    $adFullPath = [IO.Path]::GetFullPath($Path)
    if (-not $adFullPath.StartsWith($accessopsRoot + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'Directory secret path escapes the project.' }
    $adWalk = $adFullPath
    while ($adWalk.Length -gt $accessopsRoot.Length) {
        if (Test-Path -LiteralPath $adWalk) {
            if ((Get-Item -LiteralPath $adWalk -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse point in a directory secret path is refused.' }
        }
        $adWalk = [IO.Path]::GetDirectoryName($adWalk)
    }
}
Assert-ADPath $adPrivate
New-Item -ItemType Directory -Path $adPrivate -Force | Out-Null
$adCurrentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
function Protect-ADPath([string]$Path, [bool]$Directory) {
    Assert-ADPath $Path
    $adRights = if ($Directory) { '(OI)(CI)F' } else { 'F' }
    & icacls.exe $Path '/inheritance:r' '/grant:r' "*${adCurrentSid}:$adRights" '*S-1-5-18:F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Unable to protect directory connector credentials.' }
    foreach ($adRule in @((Get-Acl -LiteralPath $Path).Access)) {
        $adRuleSid = $adRule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($adRuleSid -notin @($adCurrentSid,'S-1-5-18')) {
            & icacls.exe $Path '/remove:g' "*$adRuleSid" | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Unable to remove unexpected directory credential access.' }
        }
    }
    $adAcl = Get-Acl -LiteralPath $Path
    if (-not $adAcl.AreAccessRulesProtected -or @($adAcl.Access | Where-Object {
        $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin @($adCurrentSid,'S-1-5-18')
    }).Count) { throw 'Directory credential ACL validation failed.' }
}
Protect-ADPath $adPrivate $true
$adPasswordFile = Join-Path $adPrivate 'connector-password.txt'
Assert-ADPath $adPasswordFile
Assert-ADPath (Join-Path $adPrivate 'config.json')
$adConnectorExists = Test-Path -LiteralPath $adPasswordFile
function New-ADPassword {
    $adBytes = New-Object byte[] 32
    $adGenerator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $adGenerator.GetBytes($adBytes) } finally { $adGenerator.Dispose() }
    return 'Aa1!' + [Convert]::ToBase64String($adBytes)
}
if (-not $adConnectorExists) {
    [IO.File]::WriteAllText($adPasswordFile,(New-ADPassword),[Text.UTF8Encoding]::new($false))
}
Protect-ADPath $adPasswordFile $false
$adSuffix = [Guid]::NewGuid().ToString('N').Substring(0,12)
$adFixturePassword = New-ADPassword
$adPayload = @{
    suffix=$adSuffix; connectorPassword=[IO.File]::ReadAllText($adPasswordFile)
    fixturePassword=$adFixturePassword; connectorExists=[bool]$adConnectorExists
} | ConvertTo-Json -Compress
$adPreparationPath = '/tmp/accessops-ad-prepare-' + $adSuffix + '.py'
# docker cp cannot write even a tmpfs path on this read-only container root.
# Write the reviewed source through a bounded in-container process into /tmp.
Invoke-ContainerInput ([IO.File]::ReadAllText((Join-Path $PSScriptRoot 'ad_prepare.py'))) @('exec','-i',$adDcId,'/usr/bin/python3','-c','import pathlib,sys; source=sys.stdin.read(32769); assert len(source)<=32768; pathlib.Path(sys.argv[1]).write_text(source)',$adPreparationPath)
if ($LASTEXITCODE -ne 0) { throw 'Unable to install the reviewed temporary fixture preparation helper.' }
$adPreparationSucceeded = $false
try {
$adFixtureText = Invoke-ContainerInput $adPayload @('exec','-i',$adDcId,'/usr/bin/python3',$adPreparationPath)
$adPayload = $null
if ($LASTEXITCODE -ne 0) { throw 'Scoped fixture preparation failed; newly created fixture accounts were contained where available.' }
$adFixture = $adFixtureText | ConvertFrom-Json
$adFixture | Add-Member -NotePropertyName fixturePassword -NotePropertyValue $adFixturePassword
$adFixture | Add-Member -NotePropertyName suffix -NotePropertyValue $adSuffix
$adFixturePassword = $null
$adFixturePrivate = Join-Path $accessopsRoot '.local/ad-fixtures'
Assert-ADPath $adFixturePrivate
New-Item -ItemType Directory -Path $adFixturePrivate -Force | Out-Null
Protect-ADPath $adFixturePrivate $true
$adFixturePath = Join-Path $adFixturePrivate "fixture-$adSuffix.json"
Assert-ADPath $adFixturePath
[IO.File]::WriteAllText($adFixturePath,($adFixture | ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
Protect-ADPath $adFixturePath $false
$adConfig = @{ domainGuid=$adFixture.binding.domainGuid; bindDn='CN=AccessOps-Connector,OU=AccessOps-Fixtures,DC=adlab,DC=test' }
$adConfigPath = Join-Path $adPrivate 'config.json'
if (Test-Path -LiteralPath $adConfigPath) {
    $adOldConfig = [IO.File]::ReadAllText($adConfigPath) | ConvertFrom-Json
    if ($adOldConfig.domainGuid -ne $adConfig.domainGuid -or $adOldConfig.bindDn -ne $adConfig.bindDn) { throw 'Existing connector domain differs; config replacement refused.' }
} else {
    [IO.File]::WriteAllText($adConfigPath,($adConfig | ConvertTo-Json),[Text.UTF8Encoding]::new($false))
}
Protect-ADPath $adConfigPath $false
$adPreparationSucceeded = $true
Write-Output "Scoped fixture prepared. Private harness reference: .local/ad-fixtures/fixture-$adSuffix.json"
Write-Output 'No Administrator credential was read or exported. Existing seeded users and groups were preserved.'
if ($PassThru) { Write-Output ([pscustomobject]@{ FixturePath=$adFixturePath; Suffix=$adSuffix }) }
} finally {
    $adPayload = $null
    $adFixturePassword = $null
    if (-not $adPreparationSucceeded) {
        docker exec $adDcId /usr/bin/python3 $adPreparationPath --contain-interrupted $adSuffix
        if ($LASTEXITCODE -ne 0) { Write-Warning 'Exact new fixture containment needs local review; directory history was preserved.' }
    }
}
