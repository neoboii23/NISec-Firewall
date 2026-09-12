# Vercel Deployment Guide

This repository can deploy the ORIGINE shop Flask app to Vercel. The full local
laboratory stack cannot run on Vercel because it needs separate long-running
services for the backend, WAF, Sentinel dashboard and local Supabase/Docker.

## What Vercel Will Run

Vercel runs only the root Flask WSGI app:

```text
app.py -> ORIGINE shop
```

These remain local-lab only:

```text
waf/app.py
admin_dashboard/app.py
supabase/compose.yaml
scripts/start_*.ps1
```

## Required Vercel Environment Variables

Set these in the Vercel project settings:

```text
SHOP_DATABASE_URL=postgresql+psycopg://USER:PASSWORD@HOST:PORT/DATABASE?sslmode=require
SHOP_DATABASE_SCHEMA=shop
SECRET_KEY=use-a-long-random-secret
VULNERABLE_MODE=false
LAB_MODE=false
```

If your cloud database uses `public` instead of the migrated `shop` schema, set
`SHOP_DATABASE_SCHEMA=public` or remove the variable.

Do not upload `.local/*.json` to Vercel. Those files contain local-only database
credentials.

## Save the Cloud URL Locally Once

Run this on your PC after you copy the Supabase Cloud PostgreSQL connection
string:

```powershell
cd D:\NISec
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\configure_cloud_env.ps1
```

Paste the Supabase Cloud Postgres URL when asked. The script saves:

```text
D:\NISec\.local\cloud.env
```

That private file contains:

```text
SHOP_DATABASE_URL=same cloud database URL
SHOP_DATABASE_SCHEMA=shop
SECURITY_DATABASE_URL=same cloud database URL
SECURITY_DATABASE_SCHEMA=security
SECRET_KEY=generated automatically
VULNERABLE_MODE=false
LAB_MODE=false
```

The local service launchers load `.local\cloud.env` automatically.

## Private Local WAF and Dashboard Against the Same Cloud DB

You can use the same cloud PostgreSQL database for the public shop and your
private local WAF/Sentinel data. Keep the data separated by schema:

```text
shop data       -> schema shop
WAF/Sentinel    -> schema security
```

Set only the shop variables in Vercel. On your local machine, after creating
`.local\cloud.env`, start the WAF and Sentinel dashboard normally:

```powershell
.\scripts\start_waf.ps1
.\scripts\start_dashboard.ps1
```

If you also want your local backend to use the same cloud shop data, start it
with the normal launcher too:

```powershell
.\scripts\start_backend.ps1
```

The dashboard stays private as long as you only run it on
`http://127.0.0.1:9000` and do not deploy or tunnel it.

## Database Setup

Use a cloud PostgreSQL database, such as Supabase Cloud. To copy the current
local shop and WAF/Sentinel records into an empty cloud database, run:

```powershell
cd D:\NISec
.\scripts\push_local_data_to_cloud.ps1
```

That command applies the schema and copies both schemas:

```text
shop
security
```

If you want a fresh shop with only demo products instead of copying existing
local records, run these instead:

```powershell
.\scripts\apply_cloud_schema.ps1
.\scripts\seed_cloud_shop.ps1
```

You can verify the cloud schemas later with:

```powershell
.\scripts\check_cloud_schema.ps1
```

For Supabase Cloud, use the direct or pooler PostgreSQL connection string from
Project Settings -> Database. Replace `postgres://` or `postgresql://` is okay;
the app normalizes it to the installed psycopg driver.

## Deploy

Install Vercel CLI if needed:

```powershell
npm.cmd install -g vercel
```

Preview deployment:

```powershell
cd D:\NISec
vercel
```

Production deployment:

```powershell
vercel --prod
```

## Important Limitations

- Uploaded files use temporary serverless storage on Vercel and are not
  persistent. The upload metadata is stored in PostgreSQL, but files themselves
  are not durable.
- The WAF reverse proxy and Sentinel dashboard are not deployed by this Vercel
  profile.
- Keep `VULNERABLE_MODE=false` for any public deployment.
- Static assets are duplicated under `public/static` so Vercel can serve them
  directly.
