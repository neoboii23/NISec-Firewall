Set-Location -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'waf')
& ..\.venv\Scripts\python.exe app.py
