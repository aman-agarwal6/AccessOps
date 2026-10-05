[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$accessopsRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $accessopsRoot
. (Join-Path $PSScriptRoot 'LabCompose.ps1')
$accessopsPython = Join-Path $accessopsRoot 'backend/.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $accessopsPython)) { throw 'Create backend/.venv with the hashed runtime lockfile first.' }
$accessopsReports = Join-Path $accessopsRoot 'output/connected'
New-Item -ItemType Directory -Path $accessopsReports -Force | Out-Null

# Each live suite runs in a one-shot backend container with the check scripts
# read-only and only the report folder writable; -Logins adds the operator logins.
function Invoke-LiveSuite {
    param([string]$Script, [string]$Report, [string]$Failure, [string[]]$Extra = @(), [switch]$Logins)
    $mounts = @('-v', "${accessopsRoot}/scripts:/app/scripts:ro", '-v', "${accessopsReports}:/test-output")
    if ($Logins) { $mounts += @('-v', "${accessopsRoot}/.local/operator-logins.json:/run/test-logins.json:ro") }
    $command = @('backend', 'python', "/app/scripts/$Script", '--report', "/test-output/$Report.json", '--junit', "/test-output/$Report.xml") + $Extra
    Invoke-LabCompose -Arguments (@('run', '--rm', '--no-deps') + $mounts + $command) -Failure $Failure
}

Invoke-LabNative -Command $accessopsPython -Arguments @('scripts/test_policy.py', '--report', "$accessopsReports/policy.json", '--junit', "$accessopsReports/policy.xml") -Failure 'Policy tests failed.'
Invoke-LiveSuite -Script 'live_integrations.py' -Report 'protocols' -Failure 'Live integration tests failed.'
Invoke-LiveSuite -Script 'live_oidc.py' -Report 'oidc-business' -Logins -Failure 'Real OIDC and business lifecycle checks failed.'
Invoke-LiveSuite -Script 'live_offboarding.py' -Report 'offboarding' -Logins -Extra @('--snapshot', '/test-output/connected-snapshot.json', '--principal', '/test-output/connected-principal.json') -Failure 'Connected synthetic offboarding checks failed.'
Invoke-LiveSuite -Script 'live_cases.py' -Report 'cases' -Logins -Extra @('--snapshot', '/test-output/connected-cases-snapshot.json') -Failure 'Authenticated departure case checks failed.'
if (Test-Path -LiteralPath '.local/atlas.env') {
    Invoke-LiveSuite -Script 'live_sessions.py' -Report 'sessions' -Logins -Failure 'Workforce session revocation checks failed.'
    Invoke-LiveSuite -Script 'live_hr_intake.py' -Report 'hr-intake' -Logins -Failure 'Signed HR leaver intake checks failed.'
    # Acts as the SOC receiver and acknowledges every queued signal.
    Invoke-LiveSuite -Script 'live_leaver_assurance.py' -Report 'leaver-assurance' -Logins -Failure 'Leaver assurance and signal checks failed.'
} else {
    Write-Host 'Skipped session revocation, HR intake and leaver assurance checks: run scripts/Upgrade-Lab.ps1 once to add the Atlas lab app.'
}
Invoke-LabNative -Command $accessopsPython -Arguments @('scripts/host_health.py', '--report', "$accessopsReports/host-health.json", '--junit', "$accessopsReports/host-health.xml") -Failure 'Verified host loopback TLS checks failed.'
Invoke-LabNative -Command $accessopsPython -Arguments @('scripts/record_runtime.py', '--output', "$accessopsReports/runtime-source.json") -Failure 'Running backend source differs from this checkout; rebuild the lab before recording evidence.'
Write-Host 'Sanitized, timestamped JSON and JUnit reports are in output/connected. The browser journey, dependency outages and the key rotation drill (Test-KeyRotation.ps1) run separately.'
