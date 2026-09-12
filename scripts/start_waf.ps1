. (Join-Path $PSScriptRoot 'load_cloud_env.ps1')
Set-Location -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'waf')
& ..\.venv\Scripts\python.exe app.py
