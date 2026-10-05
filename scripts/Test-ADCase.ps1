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
. (Join-Path $PSScriptRoot 'LabCompose.ps1')
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
        Invoke-LabNative -Command 'docker' -Arguments ($adCaseArgs + @('build', 'backend')) -Failure 'Directory connector image build failed.'
    }
    Invoke-LabNative -Command 'docker' -Arguments ($adCaseArgs + @('run', '--rm', '--no-deps', 'backend', 'python', 'manage.py', 'migrate', '--noinput')) -Failure 'Directory case migration failed.'
    Invoke-LabNative -Command 'docker' -Arguments ($adCaseArgs + @('up', '-d', '--wait', '--wait-timeout', '120', 'backend', 'worker')) -Failure 'Directory-connected application did not become healthy.'
    $adCaseOutput = Join-Path $adCaseRoot 'output/connected'
    New-Item -ItemType Directory -Path $adCaseOutput -Force | Out-Null
    $adCaseFailed = $false
    # Probes run in the opt-in directory-probe service: the directory image with
    # only its public CA, the fixture reference and the report folder.
    $adCaseProbe = $adCaseArgs + @('run', '--rm', '--no-deps', '-T', '-v', "${adCaseFixture}:/run/ad-fixture.json:ro", '-v', "${adCaseOutput}:/reports", 'directory-probe')
    $adCaseReady = Join-Path $adCaseOutput "ad-held-$adCaseSuffix.ready"
    $adCaseGo = Join-Path $adCaseOutput "ad-held-$adCaseSuffix.go"
    $adCaseHeld = $null
    try {
        try { Invoke-LabNative -Command 'docker' -Arguments ($adCaseProbe + @('/run/probes/ad_auth_probe.py', '--phase', 'before', '--report', "/reports/ad-auth-before-$adCaseSuffix.json")) }
        catch { $adCaseFailed = $true }
        # While the fixture user is active, hold the sessions and tickets a signed-in
        # person would have, then measure them once the case has offboarded the user.
        $adCaseHeld = Start-Job -ScriptBlock {
            param([string]$Root, [string[]]$Arguments)
            Set-Location -LiteralPath $Root
            $ErrorActionPreference = 'Continue'
            & docker @Arguments 2>&1 | ForEach-Object { "$_" }
            "exit=$LASTEXITCODE"
        } -ArgumentList $adCaseRoot, ($adCaseProbe + @('/run/probes/ad_session_probe.py', '--report', "/reports/ad-held-sessions-$adCaseSuffix.json", '--ready', "/reports/ad-held-$adCaseSuffix.ready", '--go', "/reports/ad-held-$adCaseSuffix.go"))
        $adCaseDeadline = (Get-Date).AddSeconds(120)
        while (-not (Test-Path -LiteralPath $adCaseReady) -and $adCaseHeld.State -eq 'Running' -and (Get-Date) -lt $adCaseDeadline) { Start-Sleep -Seconds 1 }
        if (-not (Test-Path -LiteralPath $adCaseReady)) { $adCaseFailed = $true; Write-Warning 'The held-session probe did not get ready.' }
        try { Invoke-LabNative -Command 'docker' -Arguments ($adCaseArgs + @('run', '--rm', '--no-deps', '-v', "${adCaseRoot}/scripts:/app/scripts:ro", '-v', "${adCaseOutput}:/test-output", '-v', "${adCaseRoot}/.local/operator-logins.json:/run/test-logins.json:ro", '-v', "${adCaseFixture}:/run/ad-fixture.json:ro", 'backend', 'python', '/app/scripts/live_cases.py', '--ad-fixture', '/run/ad-fixture.json', '--report', "/test-output/cases-ad-$adCaseSuffix.json", '--junit', "/test-output/cases-ad-$adCaseSuffix.xml", '--snapshot', '/test-output/connected-cases-ad-snapshot.json')) }
        catch { $adCaseFailed = $true }
        Set-Content -LiteralPath $adCaseGo -Value 'offboarded'
        $null = Wait-Job -Job $adCaseHeld -Timeout 180
        $adCaseHeldOutput = @(Receive-Job -Job $adCaseHeld)
        $adCaseHeldOutput | Select-Object -Last 3 | ForEach-Object { Write-Output $_ }
        if ($adCaseHeldOutput[-1] -ne 'exit=0') { $adCaseFailed = $true }
        try { Invoke-LabNative -Command 'docker' -Arguments ($adCaseProbe + @('/run/probes/ad_auth_probe.py', '--phase', 'after', '--report', "/reports/ad-auth-after-$adCaseSuffix.json")) }
        catch { $adCaseFailed = $true }
    } finally {
        if ($adCaseHeld) { Stop-Job -Job $adCaseHeld -ErrorAction SilentlyContinue; Remove-Job -Job $adCaseHeld -Force -ErrorAction SilentlyContinue }
        Remove-Item -LiteralPath $adCaseReady, $adCaseGo -ErrorAction SilentlyContinue
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
