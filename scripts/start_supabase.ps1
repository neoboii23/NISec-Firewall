# Start only this project's local stack; never reset data or contact a cloud project.
[CmdletBinding()]
param([ValidateSet('start','stop','status')][string]$Action='start')
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot

$dockerCommand = Get-Command docker.exe -ErrorAction SilentlyContinue
if (-not $dockerCommand) {
    $dockerCandidates = @(
        (Join-Path $env:LOCALAPPDATA 'Programs\DockerDesktop\resources\bin\docker.exe'),
        'C:\Program Files\Docker\Docker\resources\bin\docker.exe'
    )
    foreach ($candidate in $dockerCandidates) {
        if (Test-Path -LiteralPath $candidate) {
            $dockerCommand = Get-Command $candidate
            $env:PATH = (Split-Path -Parent $candidate) + ';' + $env:PATH
            break
        }
    }
}
if (-not $dockerCommand) {
    throw 'Docker is missing. Install Docker Desktop, start its Linux engine, then reopen PowerShell.'
}
if ($env:DOCKER_HOST -or $env:DOCKER_CONTEXT) {
    throw 'Use the local Docker Desktop context without DOCKER_HOST/DOCKER_CONTEXT overrides.'
}
$contextData = & $dockerCommand.Source context inspect 2>$null
if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect Docker context. Start Docker Desktop.' }
$context = @($contextData | ConvertFrom-Json)[0]
if ($context.Endpoints.docker.Host -notlike 'npipe://*') {
    throw 'This Windows launcher requires a local named-pipe Docker Desktop engine, not a remote daemon.'
}
$engineType = & $dockerCommand.Source info --format '{{.OSType}}' 2>$null
if ($LASTEXITCODE -ne 0 -or $engineType -ne 'linux') {
    throw 'Start Docker Desktop with Linux containers before starting Supabase.'
}

& .\.venv\Scripts\python.exe scripts/init_supabase_secrets.py
if ($LASTEXITCODE -ne 0) { throw 'Cannot initialize local Supabase configuration.' }
$composeArguments = @('compose','--env-file','.local/supabase.env','-f','supabase/compose.yaml')
if ($Action -eq 'stop') {
    & $dockerCommand.Source @composeArguments stop
} elseif ($Action -eq 'status') {
    & $dockerCommand.Source @composeArguments ps
} else {
    & $dockerCommand.Source @composeArguments up -d --wait --wait-timeout 180
}
if ($LASTEXITCODE -ne 0) { throw 'Supabase operation failed. Existing application databases were not changed.' }
if ($Action -eq 'start') { Write-Host 'Studio: http://127.0.0.1:54323 - local machine only.' }
