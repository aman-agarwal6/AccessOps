param(
    [string]$LabRoot = (Join-Path $PSScriptRoot '../infra/ad-lab'),
    [string]$FixturePath,
    [switch]$SkipBuild
)
$ErrorActionPreference = 'Stop'
# Container stdin must be UTF-8 without a BOM. Windows PowerShell 5.1 writes native
# stdin with the console input encoding, so pin it only for the duration of a pipe.
function Invoke-ContainerInput([string]$Text, [string[]]$Arguments) {
    $previousInput, $previousOutput = [Console]::InputEncoding, $OutputEncoding
    [Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
    $OutputEncoding = [Text.UTF8Encoding]::new($false)
    try { $Text | docker @Arguments } finally { [Console]::InputEncoding = $previousInput; $OutputEncoding = $previousOutput }
}
$adCaseRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$adCaseLabRoot = (Resolve-Path -LiteralPath $LabRoot).Path
$adCaseCompose = Join-Path $adCaseLabRoot 'compose.yml'
$adCaseCleanupAvailable = $false
Push-Location $adCaseRoot
try {
    if (-not $FixturePath) {
        $adCasePreparationOutput = @(& (Join-Path $PSScriptRoot 'Prepare-ADLab.ps1') -LabRoot $adCaseLabRoot -PassThru)
        foreach ($adCasePreparationItem in $adCasePreparationOutput) {
            if ($adCasePreparationItem -is [string]) { Write-Output $adCasePreparationItem }
        }
        $adCasePreparation = @($adCasePreparationOutput | Where-Object { $_ -isnot [string] -and $_.PSObject.Properties.Name -contains 'FixturePath' })
        if ($adCasePreparation.Count -ne 1) { throw 'Exact preparation result unavailable; no global fixture selection is allowed.' }
        $FixturePath = $adCasePreparation[0].FixturePath
    }
    $adCaseFixture = [IO.Path]::GetFullPath($FixturePath)
    $adCaseFixtureParent = Join-Path $adCaseRoot '.local/ad-fixtures'
    if ([IO.Path]::GetDirectoryName($adCaseFixture) -ne $adCaseFixtureParent -or [IO.Path]::GetFileName($adCaseFixture) -notmatch '^fixture-([a-f0-9]{12})\.json$') { throw 'Only the protected exact local fixture reference is accepted.' }
    $adCaseSuffix = $Matches[1]
    foreach ($adCasePrivatePath in @((Join-Path $adCaseRoot '.local'),$adCaseFixtureParent,$adCaseFixture)) {
        if ((Get-Item -LiteralPath $adCasePrivatePath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Directory fixture reparse point is refused.' }
    }
    $adCaseDc = (docker compose -f $adCaseCompose ps -q dc).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($adCaseDc)) { throw 'Explicit directory lab is not running.' }
    $adCaseOrigin = (docker inspect --format '{{json .Config.Labels}}' $adCaseDc | ConvertFrom-Json).'com.docker.compose.project.working_dir'
    if ($LASTEXITCODE -ne 0 -or [IO.Path]::GetFullPath($adCaseOrigin.Trim()) -ne $adCaseLabRoot) { throw 'Directory project origin differs from the explicit LabRoot.' }
    $adCaseCleanupPath = '/tmp/accessops-ad-cleanup-' + $adCaseSuffix + '.py'
    Invoke-ContainerInput ([IO.File]::ReadAllText((Join-Path $PSScriptRoot 'ad_prepare.py'))) @('exec','-i',$adCaseDc,'/usr/bin/python3','-c','import pathlib,sys; source=sys.stdin.read(32769); assert len(source)<=32768; pathlib.Path(sys.argv[1]).write_text(source)',$adCaseCleanupPath)
    if ($LASTEXITCODE -ne 0) { throw 'Exact fixture containment helper unavailable.' }
    $adCaseCleanupAvailable = $true
    $adCaseArgs = @('compose','-f','infra/compose.yml','-f','infra/compose.ad.yml')
    if (-not $SkipBuild) {
        & docker @adCaseArgs build backend
        if ($LASTEXITCODE -ne 0) { throw 'Directory connector image build failed.' }
    }
    & docker @adCaseArgs run --rm --no-deps backend python manage.py migrate --noinput
    if ($LASTEXITCODE -ne 0) { throw 'Directory case migration failed.' }
    & docker @adCaseArgs up -d --wait --wait-timeout 120 backend worker
    if ($LASTEXITCODE -ne 0) { throw 'Directory-connected application did not become healthy.' }
    $adCaseOutput = Join-Path $adCaseRoot 'output/connected'
    New-Item -ItemType Directory -Path $adCaseOutput -Force | Out-Null
    $adCaseFailed = $false
    try {
        foreach ($adCasePhase in @('before','after')) {
            if ($adCasePhase -eq 'after') {
                & docker @adCaseArgs run --rm --no-deps -v "${adCaseRoot}/scripts:/app/scripts:ro" -v "${adCaseOutput}:/test-output" -v "${adCaseRoot}/.local/operator-logins.json:/run/test-logins.json:ro" -v "${adCaseFixture}:/run/ad-fixture.json:ro" backend python /app/scripts/live_cases.py --ad-fixture /run/ad-fixture.json --report "/test-output/cases-ad-$adCaseSuffix.json" --junit "/test-output/cases-ad-$adCaseSuffix.xml" --snapshot /test-output/connected-cases-ad-snapshot.json
                if ($LASTEXITCODE -ne 0) { $adCaseFailed = $true }
            }
            & docker run --rm --network accessops-adlab_directory --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges --memory 192m --pids-limit 64 -v accessops-adlab_public-ca:/run/lab-ca:ro -v "${adCaseFixture}:/run/ad-fixture.json:ro" -v "${adCaseRoot}/scripts/ad_auth_probe.py:/run/ad-auth-probe.py:ro" -v "${adCaseOutput}:/reports" --entrypoint /usr/bin/python3 accessops-adlab:local /run/ad-auth-probe.py --phase $adCasePhase --report "/reports/ad-auth-$adCasePhase-$adCaseSuffix.json"
            if ($LASTEXITCODE -ne 0) { $adCaseFailed = $true }
        }
    } finally {
        docker exec $adCaseDc /usr/bin/python3 $adCaseCleanupPath --contain-interrupted $adCaseSuffix
        if ($LASTEXITCODE -ne 0) { throw 'Exact fixture/canary containment failed; preserve state for local review.' }
        $adCaseCleanupAvailable = $false
    }
    if ($adCaseFailed) { throw 'Directory case verification failed; reports and contained fixture history were preserved.' }
    Write-Output 'Directory case, delegation denials and new authentication checks passed. Exact fixture/canary accounts are disabled and history retained.'
} finally {
    if ($adCaseCleanupAvailable) {
        docker exec $adCaseDc /usr/bin/python3 $adCaseCleanupPath --contain-interrupted $adCaseSuffix
        if ($LASTEXITCODE -ne 0) { Write-Warning 'Exact new fixture containment needs local review.' }
    }
    Pop-Location
}
