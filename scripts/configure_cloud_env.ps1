param(
    [string]$DatabaseUrl,
    [string]$SecretKey
)

$projectRoot = Split-Path -Parent $PSScriptRoot
$localDir = Join-Path $projectRoot '.local'
$cloudEnvPath = Join-Path $localDir 'cloud.env'

if (-not (Test-Path -LiteralPath $localDir)) {
    New-Item -ItemType Directory -Path $localDir | Out-Null
}

if (-not $DatabaseUrl) {
    $secureUrl = Read-Host 'Paste Supabase Cloud Postgres URL' -AsSecureString
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureUrl)
    try {
        $DatabaseUrl = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    }
}

if (-not $DatabaseUrl -or $DatabaseUrl -notmatch '^postgres(ql)?(\+psycopg)?://') {
    throw 'DatabaseUrl must start with postgres://, postgresql://, or postgresql+psycopg://'
}

if (-not $SecretKey) {
    $SecretKey = & (Join-Path $projectRoot '.venv\Scripts\python.exe') -c "import secrets; print(secrets.token_urlsafe(48))"
}

$content = @(
    '# Private local cloud database settings. Do not commit this file.',
    "SHOP_DATABASE_URL=$DatabaseUrl",
    'SHOP_DATABASE_SCHEMA=shop',
    "SECURITY_DATABASE_URL=$DatabaseUrl",
    'SECURITY_DATABASE_SCHEMA=security',
    "SECRET_KEY=$SecretKey",
    'VULNERABLE_MODE=false',
    'LAB_MODE=false'
)

Set-Content -LiteralPath $cloudEnvPath -Value $content -Encoding UTF8
Write-Host "Saved private cloud settings to $cloudEnvPath"
Write-Host 'Local backend, WAF, and Sentinel launchers will load this file automatically.'
