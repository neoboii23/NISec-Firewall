# Starting Guide - ORIGINE Shop, WAF, Sentinel and Local Supabase

Use this guide to start the project on Windows with PowerShell. Project folder:
`D:\NISec`.

This is a controlled cybersecurity laboratory. Keep the vulnerable shop, WAF,
Sentinel dashboard, PostgreSQL and Studio on `127.0.0.1` unless you deliberately
set up a separate private lab tunnel or VM port-forward. Do not expose this lab
to the public Internet.

## 1. First-Time Setup

If the project is already installed and your Sentinel account exists, skip to
Section 2.

Python and the Windows `py` launcher must be installed:

```powershell
cd D:\NISec
py --version
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip install -r waf\requirements.txt
.\.venv\Scripts\python.exe -m pip install -r admin_dashboard\requirements.txt
.\.venv\Scripts\python.exe -m pip install -r lab_tests\requirements.txt
```

Create a Sentinel administrator once:

```powershell
.\.venv\Scripts\python.exe -m admin_dashboard.setup_admin --username admin
```

Enter and confirm your own password of at least 12 characters. Input is hidden.
The setup command does not overwrite an existing account. Shop demo accounts are
separate from Sentinel accounts.

## 2. Start Local Supabase

Docker Desktop must be installed and running with Linux containers. This project
uses a local database-and-Studio Supabase stack:

```powershell
cd D:\NISec
npm.cmd run db:start
```

Open Studio here:

| Tool | Address | Notes |
| --- | --- | --- |
| Supabase Studio | [http://127.0.0.1:54323](http://127.0.0.1:54323) | Rich database UI |
| PostgreSQL | `127.0.0.1:54322` | Local machine only |

In Studio, open **Table Editor**, then use the schema selector:

| Schema | Main tables |
| --- | --- |
| `security` | `security_events`, `security_alerts`, `management_audit`, WAF policies and dashboard users |
| `shop` | `user`, `item`, `comment`, `upload` |
| `legacy_archive` | Archived rows from the older lab database |

The Supabase stack intentionally runs only the database, postgres-meta and
Studio. Supabase Auth, Storage, Edge Functions, Realtime, Kong/Data API,
Analytics and Vector are not part of this local lab stack. The Flask app still
uses its own login system and filesystem upload folder.

Stop Supabase without deleting data:

```powershell
npm.cmd run db:stop
```

Do not run `supabase start`, `db reset`, `stop --no-backup`, or remove Docker
volumes for this project. The checked-in launcher uses `supabase\compose.yaml`
with explicit loopback-only port bindings.

## 3. Start the Three Services

Open three separate PowerShell terminals and keep each terminal running.

Terminal 1 - shop backend, port 5000:

```powershell
cd D:\NISec
$env:VULNERABLE_MODE = 'false'
.\.venv\Scripts\python.exe app.py
```

For intentionally vulnerable experiments in the isolated lab only, stop the
backend with Ctrl+C and restart it with:

```powershell
$env:VULNERABLE_MODE = 'true'
.\.venv\Scripts\python.exe app.py
```

Terminal 2 - WAF, port 8080:

```powershell
cd D:\NISec\waf
..\.venv\Scripts\python.exe app.py
```

Terminal 3 - Sentinel dashboard, port 9000:

```powershell
cd D:\NISec
.\.venv\Scripts\python.exe -m admin_dashboard.app
```

Convenience launchers are also available:

```powershell
.\scripts\start_backend.ps1
.\scripts\start_waf.ps1
.\scripts\start_dashboard.ps1
```

## 4. Open the Websites

| Website | Address | Sign-in |
| --- | --- | --- |
| Shop through WAF | [http://127.0.0.1:8080](http://127.0.0.1:8080) | Shop account |
| Direct backend | [http://127.0.0.1:5000](http://127.0.0.1:5000) | Bypasses WAF; comparisons only |
| Sentinel dashboard | [http://127.0.0.1:9000/login](http://127.0.0.1:9000/login) | Sentinel admin account |
| Supabase Studio | [http://127.0.0.1:54323](http://127.0.0.1:54323) | Local DB UI |

Seeded shop-only accounts:

| Username | Demo password |
| --- | --- |
| `student` | `student123` |
| `admin` | `admin123` |

Shop pages include `/login`, `/register`, `/search`, `/profile`, `/comment`,
`/upload` and `/admin`. Use port 8080 when demonstrating WAF protection.

## 5. Check Startup

1. Open the shop through `8080` and search for `tote`.
2. Sign in to Sentinel on `9000` and open **System status**. WAF, Backend,
   Dashboard and Database should be online or healthy.
3. Open **Traffic & logs**. The shop request should appear as an ALLOW event
   after the next polling cycle.
4. Open Supabase Studio, select schema `security`, and open `security_events` to
   browse the same records at database level.

## 6. Tests and Measurements

Run the suites separately:

```powershell
cd D:\NISec\waf
..\.venv\Scripts\python.exe -m pytest -q
cd D:\NISec
.\.venv\Scripts\python.exe -m pytest admin_dashboard/tests -q
.\.venv\Scripts\python.exe -m pytest lab_tests -q
```

Collect a fresh disposable before/after evaluation:

```powershell
cd D:\NISec
.\.venv\Scripts\python.exe -m lab_tests.evaluation --samples 50 --output evaluation_results
```

The evaluation harness starts temporary loopback-only services and disposable
databases. Existing performance reports are historical synthetic lab results;
they are not Supabase capacity claims.

Latest local verification after SQLite retirement on 2026-09-11:
`99 WAF + 23 dashboard + 5 lab = 127 passing tests`.

## 7. Backups and Database Notes

The SQLite data was migrated into PostgreSQL run
`20260911T093848Z-4fbf4e26`. The migration backup is:

```text
D:\NISec\backups\supabase-20260911T093848Z-4fbf4e26
```

The app stores its active database connection settings under `.local`. That
folder contains local secrets and is ignored by the project. Back up `.local`
and the Docker volume if you want to preserve this local database.

The local Supabase database uses separate least-privilege PostgreSQL roles for
the shop and WAF/Sentinel security data. The schemas are private and are not
granted to Supabase `anon` or `authenticated` roles.

## Troubleshooting

| Problem | What to check |
| --- | --- |
| Docker commands cannot connect | Start Docker Desktop and wait for the Linux engine, then run `npm.cmd run db:start`. |
| Studio opens but shows no tables | In Table Editor, switch schema from `public` to `security`, `shop` or `legacy_archive`. |
| `py` is not recognized | Install Python with the Windows launcher, or use your installed Python path directly. |
| Missing Python module | Install the relevant requirements inside `.venv`. |
| Port already in use | Use the existing service or stop only the terminal/process that owns that port. |
| Shop returns a gateway error | Start the backend on `127.0.0.1:5000` and check its terminal/log. |
| Shop has no styling on 8080 | Restart the WAF and hard-refresh the browser. CSS/JS must be proxied through 8080. |
| Dashboard login fails | Use the separate Sentinel password, not `admin123`. |
| Dashboard says WAF management unavailable | Ensure the WAF is running and both WAF and dashboard are using the same PostgreSQL security database. |
| Attack map has no public markers | Loopback/private IPs are labelled Internal / Lab Network. Public markers require an optional local GeoIP City database. |
| Evaluation says no report is available | Run the evaluation command in Section 6, then refresh Sentinel. |

For detailed controlled attack examples and the implementation record, read
[PROJECT_README.md](PROJECT_README.md).

For Vercel hosting, read [VERCEL_DEPLOYMENT.md](VERCEL_DEPLOYMENT.md). The
Vercel profile deploys only the ORIGINE shop `app.py`; the WAF, Sentinel
dashboard and local Supabase Studio remain local-lab services.
