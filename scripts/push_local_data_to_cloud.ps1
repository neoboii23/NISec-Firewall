. (Join-Path $PSScriptRoot 'load_cloud_env.ps1')
Set-Location -LiteralPath (Split-Path -Parent $PSScriptRoot)
& .\.venv\Scripts\python.exe scripts\push_local_data_to_cloud.py --yes
