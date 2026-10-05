[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$accessopsRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $accessopsRoot
$accessopsPython = Join-Path $accessopsRoot 'backend/.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $accessopsPython)) { throw 'Create backend/.venv with the hashed runtime lockfile first.' }
$accessopsReports = Join-Path $accessopsRoot 'output/connected'
New-Item -ItemType Directory -Path $accessopsReports -Force | Out-Null
& $accessopsPython scripts/test_policy.py --report "$accessopsReports/policy.json" --junit "$accessopsReports/policy.xml"
if ($LASTEXITCODE -ne 0) { throw 'Policy tests failed.' }
& docker compose -f infra/compose.yml run --rm --no-deps -v "${accessopsRoot}/scripts:/app/scripts:ro" -v "${accessopsReports}:/test-output" backend python /app/scripts/live_integrations.py --report /test-output/protocols.json --junit /test-output/protocols.xml
if ($LASTEXITCODE -ne 0) { throw 'Live integration tests failed.' }
& docker compose -f infra/compose.yml run --rm --no-deps -v "${accessopsRoot}/scripts:/app/scripts:ro" -v "${accessopsReports}:/test-output" -v "${accessopsRoot}/.local/operator-logins.json:/run/test-logins.json:ro" backend python /app/scripts/live_oidc.py --report /test-output/oidc-business.json --junit /test-output/oidc-business.xml
if ($LASTEXITCODE -ne 0) { throw 'Real OIDC and business lifecycle checks failed.' }
& docker compose -f infra/compose.yml run --rm --no-deps -v "${accessopsRoot}/scripts:/app/scripts:ro" -v "${accessopsReports}:/test-output" -v "${accessopsRoot}/.local/operator-logins.json:/run/test-logins.json:ro" backend python /app/scripts/live_offboarding.py --report /test-output/offboarding.json --junit /test-output/offboarding.xml --snapshot /test-output/connected-snapshot.json --principal /test-output/connected-principal.json
if ($LASTEXITCODE -ne 0) { throw 'Connected synthetic offboarding checks failed.' }
& docker compose -f infra/compose.yml run --rm --no-deps -v "${accessopsRoot}/scripts:/app/scripts:ro" -v "${accessopsReports}:/test-output" -v "${accessopsRoot}/.local/operator-logins.json:/run/test-logins.json:ro" backend python /app/scripts/live_cases.py --report /test-output/cases.json --junit /test-output/cases.xml --snapshot /test-output/connected-cases-snapshot.json
if ($LASTEXITCODE -ne 0) { throw 'Authenticated departure case checks failed.' }
if (Test-Path -LiteralPath '.local/atlas.env') {
    & docker compose -f infra/compose.yml run --rm --no-deps -v "${accessopsRoot}/scripts:/app/scripts:ro" -v "${accessopsReports}:/test-output" -v "${accessopsRoot}/.local/operator-logins.json:/run/test-logins.json:ro" backend python /app/scripts/live_sessions.py --report /test-output/sessions.json --junit /test-output/sessions.xml
    if ($LASTEXITCODE -ne 0) { throw 'Workforce session revocation checks failed.' }
    & docker compose -f infra/compose.yml run --rm --no-deps -v "${accessopsRoot}/scripts:/app/scripts:ro" -v "${accessopsReports}:/test-output" -v "${accessopsRoot}/.local/operator-logins.json:/run/test-logins.json:ro" backend python /app/scripts/live_hr_intake.py --report /test-output/hr-intake.json --junit /test-output/hr-intake.xml
    if ($LASTEXITCODE -ne 0) { throw 'Signed HR leaver intake checks failed.' }
    & docker compose -f infra/compose.yml run --rm --no-deps -v "${accessopsRoot}/scripts:/app/scripts:ro" -v "${accessopsReports}:/test-output" -v "${accessopsRoot}/.local/operator-logins.json:/run/test-logins.json:ro" backend python /app/scripts/live_leaver_assurance.py --report /test-output/leaver-assurance.json --junit /test-output/leaver-assurance.xml
    if ($LASTEXITCODE -ne 0) { throw 'Leaver assurance and signal checks failed.' }
} else {
    Write-Host 'Skipped session revocation, HR intake and leaver assurance checks: run scripts/Upgrade-Lab.ps1 once to add the Atlas lab app.'
}
& $accessopsPython scripts/host_health.py --report "$accessopsReports/host-health.json" --junit "$accessopsReports/host-health.xml"
if ($LASTEXITCODE -ne 0) { throw 'Verified host loopback TLS checks failed.' }
& $accessopsPython scripts/record_runtime.py --output "$accessopsReports/runtime-source.json"
if ($LASTEXITCODE -ne 0) { throw 'Running backend source differs from this checkout; rebuild the lab before recording evidence.' }
Write-Host 'Sanitized, timestamped JSON and JUnit reports are in output/connected. Browser UI, dependency outages and key rotation have separate coverage.'
