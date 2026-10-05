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
