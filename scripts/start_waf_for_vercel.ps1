param(
    [Parameter(Mandatory=$true)]
    [string]$BackendUrl
)

if ($BackendUrl -notmatch '^https?://') {
    throw "BackendUrl must start with http:// or https://"
}

. (Join-Path $PSScriptRoot 'load_cloud_env.ps1')
[Environment]::SetEnvironmentVariable('BACKEND_URL', $BackendUrl.TrimEnd('/'), 'Process')
[Environment]::SetEnvironmentVariable('WAF_HOST', '127.0.0.1', 'Process')
[Environment]::SetEnvironmentVariable('WAF_PORT', '8080', 'Process')

Set-Location -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'waf')
& ..\.venv\Scripts\python.exe app.py
