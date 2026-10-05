[CmdletBinding()]
param()
# Live Microsoft Entra departure against the lab's own test tenant (see
# scripts/live_entra.py). Needs .local/entra/lab.json with admin consent recorded,
# the connector certificate uploaded to the app registration, and a running lab.
# The backend and worker are restarted with the opt-in Entra overlay.
$ErrorActionPreference = 'Stop'
$accessopsRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $accessopsRoot
. (Join-Path $PSScriptRoot 'LabCompose.ps1')
if (-not (Test-Path -LiteralPath '.local/entra/lab.json')) { throw 'No Entra lab configuration at .local/entra/lab.json.' }
$accessopsReports = Join-Path $accessopsRoot 'output/connected'
New-Item -ItemType Directory -Path $accessopsReports -Force | Out-Null
$accessopsEntra = @('compose', '-f', 'infra/compose.yml', '-f', 'infra/compose.entra.yml')
Invoke-LabNative -Command 'docker' -Arguments ($accessopsEntra + @('up', '-d', '--wait', 'backend', 'worker')) -Failure 'The Entra-connected backend did not become healthy.'
Invoke-LabNative -Command 'docker' -Arguments ($accessopsEntra + @('run', '--rm', '--no-deps', '-v', "${accessopsRoot}/scripts:/app/scripts:ro", '-v', "${accessopsReports}:/test-output", '-v', "${accessopsRoot}/.local/operator-logins.json:/run/test-logins.json:ro", 'backend', 'python', '/app/scripts/live_entra.py', '--report', '/test-output/entra-departure.json', '--junit', '/test-output/entra-departure.xml')) -Failure 'Live Entra departure checks failed.'
Write-Host 'Live Entra departure passed. Sanitized reports: output/connected/entra-departure.json and .xml.'
