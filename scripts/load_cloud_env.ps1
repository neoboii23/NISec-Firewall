$cloudEnvPath = Join-Path (Split-Path -Parent $PSScriptRoot) '.local\cloud.env'

if (Test-Path -LiteralPath $cloudEnvPath) {
    Get-Content -LiteralPath $cloudEnvPath | ForEach-Object {
        $line = $_.Trim()
        if ($line.Length -eq 0 -or $line.StartsWith('#')) {
            return
        }
        $separator = $line.IndexOf('=')
        if ($separator -le 0) {
            return
        }
        $name = $line.Substring(0, $separator).Trim()
        $value = $line.Substring($separator + 1).Trim()
        if ($value.Length -ge 2 -and (($value.StartsWith('"') -and $value.EndsWith('"')) -or ($value.StartsWith("'") -and $value.EndsWith("'")))) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        [Environment]::SetEnvironmentVariable($name, $value, 'Process')
    }
}
