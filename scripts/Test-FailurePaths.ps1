# Only use while no other local lab scenario is running. Never removes data.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$accessopsRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $accessopsRoot
$accessopsReports = Join-Path $accessopsRoot 'output/connected'
New-Item -ItemType Directory -Path $accessopsReports -Force | Out-Null
foreach ($accessopsProbe in @(@{Service='opa'; Check='policy'}, @{Service='keycloak'; Check='identity'})) {
    try {
        & docker compose -f infra/compose.yml stop $accessopsProbe.Service
        if ($LASTEXITCODE -ne 0) { throw 'Could not stop the isolated dependency.' }
        & docker compose -f infra/compose.yml run --rm --no-deps -v "${accessopsRoot}/scripts:/app/scripts:ro" -v "${accessopsReports}:/test-output" backend python /app/scripts/live_failure.py $accessopsProbe.Check --report "/test-output/$($accessopsProbe.Check)-outage.json" --junit "/test-output/$($accessopsProbe.Check)-outage.xml"
        if ($LASTEXITCODE -ne 0) { throw 'A dependency outage did not fail closed.' }
    } finally {
        & docker compose -f infra/compose.yml up -d --wait --wait-timeout 120 $accessopsProbe.Service
        if ($LASTEXITCODE -ne 0) { throw 'Restore the stopped AccessOps dependency before using the lab.' }
    }
}
Write-Host 'Outage reports are in output/connected. OPA and Keycloak were restored.'
