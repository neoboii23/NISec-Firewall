Set-Location -LiteralPath (Split-Path -Parent $PSScriptRoot)
. (Join-Path $PSScriptRoot 'load_cloud_env.ps1')
& .\.venv\Scripts\python.exe -m admin_dashboard.app
