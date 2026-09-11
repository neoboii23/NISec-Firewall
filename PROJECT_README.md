# ORIGINE WAF Laboratory — Storefront, Detection and Admin Dashboard

## Current Supabase Status

The active shop, WAF and Sentinel dashboard data now lives in a local
Supabase-compatible PostgreSQL 17 database with Studio at
[http://127.0.0.1:54323](http://127.0.0.1:54323). The app uses direct
PostgreSQL connections, not Supabase Auth or the Data API. Studio is for
database inspection: open Table Editor and switch from `public` to `security`,
`shop` or `legacy_archive`.

The migration run `20260911T093848Z-4fbf4e26` imported the original shop data,
security history, Sentinel admin account, alerts, audit records and older lab
database rows. The migration backup is
`D:\NISec\backups\supabase-20260911T093848Z-4fbf4e26`. Local connection secrets
are stored under `.local` and are intentionally ignored by the project.

Run the local database stack before starting the Flask services:

```powershell
cd D:\NISec
npm.cmd run db:start
```

This project uses `supabase\compose.yaml` with explicit `127.0.0.1` port
bindings. Do not run `supabase start`, `db reset`, or remove Docker volumes for
this lab.

Verification after SQLite retirement on 2026-09-11:
**99 WAF tests + 23 dashboard tests + 5 lab tests = 127 passing tests**. Live
loopback checks confirmed the backend, WAF storefront, Sentinel login page,
Studio, and a blocked WAF-001 SQL injection event stored in PostgreSQL.

## Phases 6-18 implementation record

Work is recorded here because this workspace is not a Git repository. Baseline: 104 passing tests. The three independent services and existing detection pipeline are retained.

### Phase 6 — completed

Extended the existing `ip_policies` table additively with source, attack category and trust mode. IPv4/IPv6 policies support permanent or expiring blacklists, automatic/manual origins and temporary blocks. Dashboard policy tabs and trust controls update the running WAF on its next request. NORMAL remains the whitelist default; RATE_LIMIT_BYPASS skips only the generic limiter, BLACKLIST_BYPASS skips only blacklists, and explicitly confirmed FULL_BYPASS skips policy blocking and attack inspection but never hard transport limits. This supersedes the earlier label-only whitelist limitation. Validation: 95 WAF + 11 dashboard tests passed, including real three-service blacklist-bypass enforcement while attack inspection remains active.

### Phase 7 — completed

`/rate-limits` and GET/PUT `/api/rate-limits` manage persisted rate, login and repeated-attack thresholds. The running WAF reads changes on its next request, with accurate Retry-After for generic limiting and temporary policies. Automatic repeated-attack blocking is opt-in (`auto_enabled=false` initially), requires at least two high-confidence blocked detections of the same selected category in a bounded time window, and creates a temporary policy with category/incident/source metadata. Existing recent attack history contributes after enabling it. Brute-force response-confirmed blocking remains independently enabled. Validation: 97 WAF + 11 dashboard tests passed, including live threshold changes and automatic policy enforcement.

### Phase 8 — completed

Retained the single SQLite security database. Added portable SQLAlchemy mappings for AdminUser, FirewallRule, BlockedIP, TrustedIP, SecurityEvent, RequestLog, SecurityAlert, RateLimitRecord and AdminAuditLog. RequestLog and IP models read views of existing records, not duplicate event stores. Actual 429 events create related rate-limit records; extra indexes and old/new audit fields use additive, repeatable migrations. MySQL is not configured: migrating later also requires porting SQLite-specific aggregation/upsert/view queries. Validation: 98 WAF + 11 dashboard tests passed, including ORM reads, idempotent migration and three-service integration.

### Phase 9 — completed

Reused the existing real-data overview, summary APIs and three-second polling. Added backend health on the overview alongside WAF status. No fake metrics or new event source. Validation: all 11 dashboard tests, including live traffic/count/status integration, passed; the unchanged WAF baseline remains 98 passing tests.

### Phase 10 — completed

Added authenticated `/live-traffic`, reusing the existing parameterized event filters and three-second polling. Each refresh replaces at most 25 browser rows; pagination and source/action/category/method/severity filters remain server-side. Validation: 12 dashboard tests passed, including protected-route, row-bound and real TCP checks. WAF logic was unchanged.

### Phase 11 — completed

Added `/analytics` as a compatible alias for `/attacks`, with last-hour/24-hour/7-day/30-day and bounded custom UTC ranges. Category, severity, decisions, top-IP and top-path aggregates are computed in SQL over the selected interval; the timeline uses 60 bounded buckets. Added timeline and decision charts to analytics. Existing overview endpoints retain compatible defaults. Validation: 13 dashboard tests passed including empty/invalid/custom ranges and live six-category aggregates.

### Phase 12 — implemented; optional GeoIP data required for public markers

Added authenticated `/attack-map` and `/api/attack-map`, showing the top 100 actual attack sources and an offline longitude/latitude map with clickable source details. Non-public addresses never receive invented coordinates. Public IPs are resolved only from an optional local MaxMind-format database; results are cached for 24 hours and invalidated when that database changes. No external lookup API or map tiles are used. Install `admin_dashboard/requirements-geoip.txt` and set `GEOIP_DATABASE` to your licensed City `.mmdb` file before starting the dashboard. No such database was supplied, so public geolocation is explicitly unavailable in this workspace. Reader API follows the [MaxMind Python reader documentation](https://github.com/maxmind/MaxMind-DB-Reader-python/blob/main/README.rst). Validation: 14 dashboard tests passed, including actual loopback events labelled Internal / Lab Network and unlocated public-address behavior.

### Phase 13 — completed

Rule editing adds live score (0–100), severity, BLOCK/LOG/ALERT/TEMPORARY_BLOCK/RATE_LIMIT actions and up to five bounded literal signatures on signature-backed rules. Built-in regular expressions remain read-only to avoid unsafe dynamic regex execution. The `/api/rules/<id>/configuration` PUT API persists changes; `/api/audit` returns 25-row change history including actor, timestamp and old/new values. Detector/rule toggles remain compatible. LOG/ALERT scores do not independently contribute to blocking; ALERT explicitly requests an alert. TEMPORARY_BLOCK creates a persisted block after a blocked match. Validation: 99 WAF + 15 dashboard tests passed, including real action enforcement changes and audit values.

### Phase 14 — completed

Added `/logs` and `/logs/<incident_id>` compatible routes backed by the same event service. Logs include matched rules, exact rule filtering, existing server-side time/IP/action/category filters, pagination and filtered exports. Incident detail includes active IP policies alongside evidence and related alert state. No raw credentials or request bodies are exposed. Validation: 16 dashboard tests passed including live incident and matched-rule filtering checks.

### Phase 15 — completed

Added ADMIN/VIEWER roles to existing administrator accounts (existing accounts migrate to ADMIN). VIEWER may read dashboard data but every management mutation is rejected server-side. Create a viewer locally with `python -m admin_dashboard.setup_admin --username reviewer --role VIEWER`. `/settings` displays permissions and paginated audit history; login/logout and IP changes are audited. Sessions expire 30 minutes after sign-in and polling no longer renews them. Existing CSRF, password hashing, HttpOnly/SameSite and output protections remain. Validation: 99 WAF + 18 dashboard tests passed, including expired-session rejection and actual viewer API denial over TCP.

### Phase 16 — completed as portable testing support

Added `lab_tests/controlled_requests.py` with harmless synthetic inputs for all six categories and a six-attempt login sequence. Run `python -m lab_tests.controlled_requests --url http://127.0.0.1:8080 --confirm-local-lab` against a clean lab WAF state. It reports observed HTTP statuses, not inferred exploitation. It rejects public/LAN/DNS targets and disables redirects/proxy-environment use. Existing blocks or custom thresholds can make smoke expectations fail; use the disposable integration test for a clean baseline.

On Kali, run the same Python module from a local project checkout after installing dependencies. If Kali is a different VM, use a separately authorized SSH port-forward to the host's loopback WAF; do not expose the vulnerable backend or dashboard on public interfaces. No Kali VM was available here, so the portable suite was executed on Windows only. `python -m pytest lab_tests -q` passed both tests, including six actual attack cases against disposable backend/WAF processes. Windows cleanup now terminates only test-owned process trees. Startup convenience scripts are in `scripts/start_backend.ps1`, `scripts/start_waf.ps1`, and `scripts/start_dashboard.ps1`.

### Phase 17 — completed

`python -m lab_tests.comparison --output evaluation_results` starts separate disposable labs for direct and protected runs, uses identical synthetic cases and writes observed JSON/CSV comparison artifacts. Recorded results: SQLi returned six catalog rows versus zero in its unmatched baseline; stored XSS markup rendered unescaped (browser execution was not attempted); traversal returned a harmless out-of-directory canary; six wrong logins were unthrottled without WAF; a disallowed file extension was stored without executing it. The backend has **no command-execution sink**, so that case reports pattern acceptance, not demonstrated command execution. All six protected scenarios were detected and blocked (five 403 cases, brute force 429) with zero backend arrivals for the blocked requests. Three lab tests passed, including the full paired comparison. These observations are not broad coverage claims.

### Phase 18 — completed

Added a repeatable effectiveness/performance framework and authenticated `/evaluation` page. Reports contain actual event-backed detection decisions, before/after observations, seven legitimate workflows, latency samples, sequential throughput, server CPU time and sampled RSS. Missing reports display unavailable rather than invented values. Each full run saves a run-specific JSON file and atomically refreshes the latest report. Validation on 2026-09-10: **99 WAF + 19 dashboard + 5 laboratory tests = 123 passing tests**, including real disposable-service comparisons, measurements, authentication and management integration. The two legacy proxy smoke tests now use temporary event stores so rerunning them no longer adds synthetic events to the demonstration history; existing history was preserved.

## Project completion report — Phases 6–18

The implementation retains all three independent services and the six existing detection modules. Phases 6–11, 13–15 and 17–18 are implemented and tested. Phase 12's map/cache implementation is tested but needs an optional local GeoIP database for public markers. Phase 16's portable controlled tests work on Windows; execution on an actual Kali VM remains pending. These external checks are not declared complete.

### Actual collected evaluation

Run `986238d23af34073ac45c7c474279a6b`, collected 2026-09-10 05:16:00 UTC, dataset `synthetic-v1`:

- Six attack scenarios: TP 6, FN 0; all six detected and blocked. Brute force is one six-request scenario, not six independent attacks.
- Seven legitimate workflows: TN 7, FP 0, covering registration, login, search, profile, comment, upload and download.
- Detection/blocking/precision/recall: 100% **on this small dataset only**; false positive rate: 0% on seven cases. This is not a representative coverage or general security claim.

| Measurement | Direct backend | Protected through WAF |
| --- | ---: | ---: |
| Measured requests | 50 | 50 |
| Mean response time | 11.36 ms | 37.19 ms |
| Median response time | 14.23 ms | 36.49 ms |
| P95 response time | 25.07 ms | 65.73 ms |
| Sequential requests/second | 87.77 | 26.84 |
| Server CPU (% of one core) | 24.68% | 49.49% |
| Maximum sampled RSS | 66.07 MiB | 108.38 MiB |
| Successful responses | 50/50 | 50/50 |

Observed mean overhead: **25.82 ms (+227.26%)**. Five warmups precede each batch, with direct measured before protected. Protected CPU/RSS includes both WAF and backend; direct includes backend only. Rate limiting is disabled only in the disposable benchmark configuration. These loopback development-server measurements include proxy, network and logging costs, not pure detector time. Batch order, host noise, a single client and sparse memory sampling limit interpretation; this is not a capacity test.

Artifacts: [latest evaluation](evaluation_results/evaluation.json), [run-specific report](evaluation_results/evaluation-986238d23af34073ac45c7c474279a6b.json), [comparison CSV](evaluation_results/comparison.csv), and [comparison JSON](evaluation_results/comparison.json). View the same collected data at [Dashboard Evaluation](http://127.0.0.1:9000/evaluation).

### Repeatable verification

From an activated virtual environment in the project root:

```powershell
pip install -r lab_tests/requirements.txt
python -m pytest admin_dashboard/tests -q
python -m pytest lab_tests -q
python -m lab_tests.comparison --output evaluation_results
python -m lab_tests.evaluation --samples 50 --output evaluation_results
cd waf
python -m pytest -q
```

Comparison/evaluation start fresh loopback-only services on temporary ports, seed synthetic accounts and stop only their own process trees. They do not change the running demonstration's security policies. Preserve run-specific reports when comparing later runs. The standalone controlled-request CLI is a smoke tool for an explicitly authorized loopback lab; event-backed evaluation is provided by the disposable framework.

### Files created and modified in this continuation

Created `waf/management/runtime.py`, `waf/management/orm_models.py`, policy/runtime/schema/rule tests, dashboard services `time_range.py`, `geo_service.py`, `evaluation_service.py`, extended dashboard tests, templates for rate limits/map/settings/evaluation, `static/css/extensions.css`, optional GeoIP requirements, the `lab_tests/` cases/service harness/comparison/evaluation/tests/dependencies, three `scripts/start_*.ps1` launchers, and measured `evaluation_results/` artifacts.

Modified the existing WAF app, management store, event models, rule engine, prevention decisions, generic limiter and brute-force tracking; dashboard app/config/setup/auth/event/IP/rule/overview services, base/events/incident/rules/IP/analytics/overview templates and dashboard JavaScript; dependencies and live integration harnesses; and this single combined guide. The target's existing laboratory features were reused, not rebuilt.

### Database and integration summary

This section records the SQLite-era design before the Supabase migration. The
active security store is now PostgreSQL schema `security`; the active shop store
is PostgreSQL schema `shop`. The old SQLite records were imported and verified
before the application connection files were switched to PostgreSQL.

In the earlier SQLite phase, the sole production security store was
`waf/database/waf.db`. Additive migrations extended IP policy metadata,
administrator roles and audit old/new values, and added `firewall_rules`,
`rate_limit_records` and `geo_cache`. `blocked_ips`, `trusted_ips` and
`request_logs` were views over existing records. SQLAlchemy mappings covered all
nine requested model concepts without duplicating event storage.

Requests retain source-IP/size checks, trust policy, blacklist/temporary block, rate limiting, inspection/normalization, six detection categories, scoring and prevention. Decisions produce events, configured alerts and eligible automatic policies. Dashboard changes are authenticated, authorized, CSRF-checked, audited and persisted; the next WAF request reads them without a restart. WAF `/internal/status` remains loopback-and-token protected, with the bearer token kept server-side.

### Final demonstration and acceptance notes

Start the three foreground services in separate terminals using `scripts/start_backend.ps1`, `scripts/start_waf.ps1` and `scripts/start_dashboard.ps1`; detailed commands and provisioning follow below. Backend vulnerable mode is opt-in (`$env:VULNERABLE_MODE='true'` in its isolated lab terminal). The evaluation harness enables it only for disposable target processes.

1. Show a legitimate storefront search through 8080, then its real event in Live Traffic and the overview.
2. Run the controlled cases in a disposable lab; show six categories, 403/429 results and redacted evidence. Do not present command-pattern acceptance as OS execution, or unescaped XSS markup as a browser-execution test.
3. Demonstrate temporary/expiring IP policy, NORMAL trust, rate thresholds and rule action changes using test-owned services; restore any deliberately changed demonstration policies.
4. Show range-filtered analytics, exact-rule log search, exports, audit old/new values, and a VIEWER account's server-enforced read-only access.
5. Show Attack Source Map lab classification without invented coordinates, then Evaluation with the recorded run ID and limitations.

Desktop browser verification confirmed rendered evaluation values and System Status reporting WAF/backend/dashboard online and database healthy on 8080/5000/9000. Existing automated tests cover policy expiration, real enforcement, prevention, alerts, exports and session/CSRF/role boundaries. Remaining acceptance work is optional licensed GeoIP data and public-marker verification, actual Kali execution, and manual narrow/mobile visual verification. Single-process counters, SQLite migration effort, limited signatures/file inspection and development-server deployment remain documented limitations; this is not production-ready security software.

This project contains an ORIGINE bag-store Flask application with an opt-in vulnerable mode, a **separate** reverse-proxy Web Application Firewall (WAF), and the **independent Sentinel admin dashboard**. It is exclusively for controlled, authorized cybersecurity laboratory work; do not expose these services to the public Internet. This is the combined installation, demonstration and testing guide.

## Architecture

```text
Browser -> WAF (127.0.0.1:8080) -> Flask target (127.0.0.1:5000) -> PostgreSQL schema shop
Administrator -> Sentinel (127.0.0.1:9000) -> PostgreSQL schema security
Developer -> Supabase Studio (127.0.0.1:54323) -> schemas security, shop, legacy_archive
```

The Flask target records application requests in `logs/app.log`. The WAF
records structured security events in PostgreSQL and in `waf/logs/`.

## Install

From `D:\NISec`:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -r .\waf\requirements.txt
pip install -r .\admin_dashboard\requirements.txt
pip install -r .\lab_tests\requirements.txt
py seed.py
```

Storefront demo accounts are `admin` / `admin123` and `student` / `student123`. These do **not** authenticate to the separate security dashboard.

## Run the demonstration

Terminal 1 — start the backend only on loopback (vulnerability demonstrations require the explicit opt-in shown):

```powershell
cd D:\NISec
.\.venv\Scripts\Activate.ps1
$env:VULNERABLE_MODE = 'true' # Isolated laboratory only; omit for protected target behavior.
py app.py
```

Terminal 2 — start the standalone WAF:

```powershell
cd D:\NISec\waf
..\.venv\Scripts\Activate.ps1
py app.py
```

Use `http://127.0.0.1:8080` in the browser. Port 5000 is the backend and should not be used directly during WAF demonstrations.

Create a dashboard administrator once, from `D:\NISec` (skip if already provisioned):

```powershell
.\.venv\Scripts\python.exe -m admin_dashboard.setup_admin --username admin
```

Enter a password of at least 12 characters at the hidden prompts. Alternatively add `--generate` to print a random password once; save it privately. Only a password hash is persisted. The setup command refuses to overwrite an existing account. A separate username can be provisioned with `--username reviewer` if needed. Never commit credentials to this guide or source files.

Terminal 3 — start the independent dashboard:

```powershell
cd D:\NISec
.\.venv\Scripts\python.exe -m admin_dashboard.app
```

Open [Sentinel admin](http://127.0.0.1:9000) and sign in with the dashboard credentials. Keep all three terminals running. Stop each foreground service with Ctrl+C. After pulling code changes, restart the affected service; the Flask development servers deliberately have debug/reload disabled.

## Flask application (Phase 2)

| Route | Purpose |
| --- | --- |
| `/` | ORIGINE storefront and bag collection |
| `/register`, `/login`, `/logout` | Account lifecycle |
| `/search` | Catalog search |
| `/profile`, `/profile/edit` | Authenticated profile and update page |
| `/comment` | Authenticated product comments |
| `/upload` | Authenticated reference-file upload |
| `/download?file=readme.txt` | Dedicated laboratory download area |
| `/admin` | Administrator-only dashboard |

The profile link opens in a new browser tab. Normal users are redirected to login for protected routes and receive `403` for `/admin`.

`LAB_MODE` is enabled by default; `VULNERABLE_MODE` is disabled by default. Secure mode uses SQLAlchemy queries, escaped comments, upload restrictions, and safe file serving. For an isolated experiment only:

```powershell
$env:VULNERABLE_MODE = "true"
py app.py
```

This enables isolated SQL injection, stored XSS, traversal, and relaxed upload-validation test points. Never enable it outside the lab.

## WAF (Phase 3)

The WAF reverse-proxy supports GET, POST, PUT, PATCH, DELETE, OPTIONS, and HEAD. Its engine creates a framework-independent request context containing source IP, method, URL, path, query values, headers, cookies, user agent, body, content metadata, and multipart-file metadata.

Before matching, it performs bounded repeated URL decoding, HTML-entity decoding, Unicode normalization, case and whitespace normalization, null-byte removal, and slash normalization. Original request bytes remain unchanged for forwarding; logged evidence follows the Phase 4 redaction policy below.

Rules are editable JSON files in `waf/rules/` for:

- SQL injection
- Cross-site scripting
- Path traversal
- Command injection
- Malicious file uploads
- Scanner user agents

Matches contribute configured points. Requests scoring 7 or higher are blocked with an incident ID and a `403` page. Lower scores are logged and forwarded. Rate limiting is in-memory and returns `429` when the configured per-IP threshold is exceeded.

Configuration lives in [waf/config.py](D:/NISec/waf/config.py) and is overridden with environment variables such as `WAF_PORT`, `BACKEND_URL`, `TRUST_PROXY_HEADERS`, `RATE_LIMIT_REQUESTS`, `MAX_BODY_SIZE`, and `BLOCK_SCORE`. Proxy headers are not trusted by default.

Useful WAF endpoints:

- `GET /health` — service and backend availability
- `GET /status` — enabled-rule count and aggregate event counts

## Logging and dashboard data

The WAF `security_events` table stores timestamp, source IP, method, path,
query, user agent, category, rule IDs, severity, score, decision, incident ID,
and response status. In the active setup this table is
`security.security_events` in PostgreSQL; disposable tests can still use
temporary SQLite files. The dashboard reads the same indexed database, not a
copy. Machine-readable JSON events go to `waf/logs/security.log`; access events
go to `waf/logs/access.log`. Sensitive fields are redacted as described below.

## Tests

```powershell
cd D:\NISec\waf
..\.venv\Scripts\python.exe -m pytest -q
```

The test suite covers decoding normalization, normal “union” searches (false-positive protection), SQLi, XSS, traversal, command injection, upload metadata, rate limiting, health, and pre-forwarding blocks.

For the manual flow: register, log in, search, open Profile, edit it, post a comment, upload an allowed test file, download `readme.txt`, then log out. For the WAF flow, run both services and use port 8080: a normal search should be forwarded, while a detected malicious request receives `403` and creates a WAF event.

## Phase 4 — Attack Detection

Phase 4 extends the existing proxy, request context, JSON rule engine, normalizer, scoring and SQLite event store. It adds six modules under `waf/detectors/` and a pipeline in `waf/engine/detector.py`.

| ID | Attack | Detection | Response |
| --- | --- | --- | --- |
| WAF-001 | SQL Injection | Contextual boolean comparisons, UNION SELECT, SQL comments, stacked statements, delays | 403 |
| WAF-002 | Cross-Site Scripting | Script elements, HTML event handlers, JavaScript URIs, active embedded HTML | 403 |
| WAF-003 | Command Injection | Separators combined with commands, substitution, shell options and redirection | 403 for strong matches |
| WAF-004 | Directory Traversal | Decoded parent paths, mixed slashes, absolute paths, virtual-root checks for download filenames | 403 |
| WAF-005 | Brute Force | Backend-confirmed failed logins, tracked by IP, account hash and IP/account pair | 429 for future attempts during lockout |
| WAF-006 | Malicious File Upload | Extension chain, MIME, magic bytes, filename, size and bounded content inspection | 403 or 413 for size |

### Configuration and enabling detectors

Edit [attack_detection.json](D:/NISec/waf/config/attack_detection.json), then restart the WAF. Each of `sql_injection`, `xss`, `command_injection`, `directory_traversal`, `brute_force`, and `file_upload` has an `enabled` setting. Set it to `false` to disable that detector. Rule JSON files in `waf/rules/` also support individual `enabled`, `score`, `severity`, and `action` settings. `action: "LOG"` records a match without making it independently block a request. Restart after rule edits.

Defaults:

- Normalize at most four decoding passes.
- Five failed logins in 300 seconds start a 600-second temporary login block. State is bounded to 10,000 entries.
- File limit: 1 MiB per file; content inspection: first 65,536 bytes. Allowed extensions and MIME types are mapped in the JSON.
- Overall HTTP request limit: 2 MiB including multipart overhead, controlled by `MAX_BODY_SIZE`. Raise this too if increasing the per-file limit.
- `BLOCK_SCORE=7`. Each rule contributes once per request. Multiple matches combine; multiple strong matches totaling at least 11 produce CRITICAL severity.
- Weak command punctuation is low-confidence; ordinary semicolons, ampersands and pipes do not independently trigger a block.

### Login outcome contract

Phase 2's login handler now returns `X-Lab-Auth-Result: success` or `failure` only after checking credentials. The proxy observes this backend response and removes that header before replying to the browser. The request cannot set its own authentication result. Unknown outcomes and backend errors do not increment failure counters.

The fifth failed login is forwarded and logged as an ALLOW event with a BRUTE_FORCE match and threshold evidence. The next login request is blocked with 429 and a Retry-After header. Successful authentication before lockout clears the relevant counters. Expired state is pruned on login activity. Aggregate IP and account limits intentionally affect attempts that change only the username or only the source IP.

### Evidence, privacy and dashboard fields

New and migrated SQLite records expose `category_code` and `category_name`. Each new record also has a `categories` JSON array for requests matching multiple attack types, redacted `evidence`, and `metadata` such as the authentication outcome. The existing Phase 3 event history is retained, with legacy traversal/upload category labels aligned to the Phase 4 names.

Exact analytics categories: SQL_INJECTION, XSS, COMMAND_INJECTION, DIRECTORY_TRAVERSAL, BRUTE_FORCE, MALICIOUS_FILE_UPLOAD. `SecurityEventStore.attack_counts()` and `/status` expose category totals for the next dashboard phase.

JSON log files and database rows use the same incident ID and timestamp. Query
values are redacted in request summaries. Password, identity, session-cookie,
sensitive-header, and unstructured-body evidence is redacted. Brute-force
account identifiers use a process-local HMAC hash. Uploaded contents are
inspected in memory and never included in evidence or executed. Historical Phase
3 logs are retained as they were; the new redaction policy applies to new
events.

### Automated tests and live validation

Run all Phase 3 regressions and Phase 4 tests:

```powershell
cd D:\NISec\waf
..\.venv\Scripts\python.exe -m pytest -q -s
```

The live integration test starts the actual Phase 2 app and WAF in separate processes, uses temporary databases/uploads, and checks real TCP traffic. It prefers ports 5000/8080; if those ports are occupied it prints the temporary ports used. It stops only its own test processes afterward.

Coverage includes the normal account/search/comment/upload/download workflow; CSS forwarding; session cookies; encoded attacks; all six categories; false-positive samples; malformed and oversized requests; rule toggles; multi-match scoring; password redaction; deterministic lockout/reset/expiry tests. For each blocked attack the live test compares the backend arrival log before and after the request and requires zero new backend arrivals.

### Presentation examples

Start both services with the commands above, then browse [the WAF storefront](http://127.0.0.1:8080). Login with the seeded student account for normal comments and uploads.

- SQLi: visit `/search?q=%27%20OR%201%3D1--` through port 8080.
- XSS: submit `<script>alert(1)</script>` as a comment. The WAF blocks it before storage.
- Command injection: search for `127.0.0.1;whoami`. The WAF detects the pattern; it executes nothing.
- Traversal: request `/download?file=..%2Fdatabase.db`.
- Brute force: log out, submit the same identity with a wrong password five times, then retry. The sixth request returns 429.
- Upload: submit a harmless text file named `sample.php`, or a text file larger than the configured limit. Expect 403 or 413. Use synthetic samples only.

Inspect `waf/logs/security.log`, Supabase Studio's `security.security_events`
table, and `/status` to show the rule IDs, incidents and category counts. A
representative strong match is blocked before forwarding; the Phase 2 access log
therefore has no corresponding attack request.

### Limitations

This is a signature-based academic WAF. It cannot recognize every SQL dialect, JavaScript context, shell language or obfuscation. Educational text containing complete executable attack syntax can still trigger a match. File checks cover metadata, simple magic bytes and a bounded prefix, not antivirus scanning or full document parsing; archives and content beyond the prefix are not deeply inspected.

Normalization is for detection only. The WAF has no access to the backend filesystem: download containment uses a virtual directory and rejects escape syntax, but cannot inspect backend symlinks. The backend's protected mode should still use safe path handling.

Brute-force counters are in memory and reset on restart; multiple WAF workers require shared state. Active temporary IP policies persist in the shared database until expiry. The login-result contract must be updated if authentication moves to another backend. Generic rate limiting is separate from failed-login tracking. Editing built-in JSON definitions requires a restart; dashboard-managed toggles, scores, actions, bounded literal signatures and runtime thresholds apply on the next WAF request without a restart.

## Separate Sentinel Admin Dashboard

### Pages and charts

Navigation cleanup: all sidebar links now share the same icon, spacing and active-state design, grouped under Monitor, Protect and Workspace. Redundant Live Traffic / Security Events / Security Logs-Export entries are consolidated into **Traffic & logs**, with polling, filters and exports retained. Existing `/live-traffic`, `/events` and `/logs` routes remain compatible. All 21 dashboard tests pass, including unique navigation destinations and active states across every page and alias. This UI-only change does not remove security features or stored data.

| Dashboard route (port 9000) | Function |
| --- | --- |
| `/login`, POST `/logout` | Independent administrator authentication |
| `/`, `/dashboard` | Eight summary cards, live recent requests and four charts |
| `/events` | Filtered events, 25-row server-side pagination, CSV/JSON export |
| `/events/<incident_id>` | Redacted incident evidence, matched rules and alert status |
| `/attacks` | Six-category analytics, top-IP and top-endpoint charts |
| `/alerts` | HIGH/CRITICAL detection alerts and acknowledgement |
| `/rules` | Individual rule and six detector enable/disable controls |
| `/ip-management` | Temporary blocks, blacklist, whitelist and removal controls |
| `/system` | WAF/backend/dashboard/database status and live limiter state |
| `/live-traffic` | Bounded near-real-time traffic and filters |
| `/analytics` | Range-filtered analytics; compatible alias of `/attacks` |
| `/attack-map` | Real source-IP aggregation and optional offline public GeoIP |
| `/rate-limits` | Live counters and persisted rate/brute/automatic-block thresholds |
| `/logs`, `/logs/<incident_id>` | Search/export and incident detail aliases |
| `/settings` | Role permissions and administrator audit history |
| `/evaluation` | Collected before/after and performance reports |

The dark responsive interface polls JSON APIs every three seconds without reloading the page. Charts use the bundled local Chart.js 4.4.8 build; Internet access is not required. Its MIT license and attribution are under `admin_dashboard/static/vendor/`.

Six charts show the last 60 minutes of traffic/threats, attack categories, severity, firewall decisions, top sources and top targeted endpoints. Summary cards show total requests, allowed requests, blocked requests, detected attacks, critical attacks, active alerts, temporary blocked IPs and rate-limited requests. Times are UTC.

Counts are actual persisted WAF events; no demonstration metrics are injected into the working database. ALLOW describes the WAF decision, not necessarily successful backend authentication or an HTTP 200. BLOCK and RATE_LIMIT have separate summary cards; the timeline's stopped count includes both. A multi-category event counts once in total attacks but once in each matched category, so category percentages can sum above 100%. Dashboard polling does not generate security events. WAF `/health` and `/status` checks do generate events.

### Dashboard APIs

All APIs require a dashboard session. Mutating requests also require the ADMIN role and the session's `X-CSRF-Token` (provided automatically by the UI). VIEWER can read data but cannot change security state.

| Method | API | Result / action |
| --- | --- | --- |
| GET | `/api/dashboard/summary` | Eight card counts plus high severity count |
| GET | `/api/events/recent` | Filtered, paginated security events |
| GET | `/api/attacks/stats` | Category, severity, action and top-source/endpoint aggregates |
| GET | `/api/charts/attacks` | 60 bounded timeline buckets over the selected range (default one hour) |
| GET | `/api/alerts`, `/api/alerts/recent` | Paginated alerts; `active=true` filters unacknowledged |
| POST | `/api/alerts/<id>/acknowledge` | Acknowledge a real alert |
| GET | `/api/rules` | Rule and detector inventory with effective toggle states |
| PUT | `/api/rules/<id>` | Set `{"enabled": true}` or `false` |
| PUT | `/api/detectors/<id>` | Set detector enabled state |
| GET | `/api/ip/blocked` | Active temporary/blacklist/whitelist policies; optional `ip` search |
| POST | `/api/ip` | `operation` add/remove, `kind`, `ip`, optional `reason` and `duration` seconds |
| GET | `/api/system/status`, `/api/status` | Sanitized service health and WAF in-memory counters |
| GET | `/api/events/export` | Filtered `format=csv` or `format=json` download, maximum 10,000 records |
| GET, PUT | `/api/rate-limits` | Current runtime thresholds; validated persisted configuration changes |
| PUT | `/api/rules/<id>/configuration` | Score, severity, action and supported literal signatures |
| GET | `/api/audit` | Paginated administrator change history with old/new values |
| GET | `/api/attack-map` | Top actual attack-source records and nullable cached geolocation |
| GET | `/api/evaluation` | Available collected report; never starts a benchmark |

Event filters: `source_ip`, `incident_id`, `category`, `severity`, `action`, `method`, `start`, `end`, `path`, `rule`, and `page`. Dates use ISO format; the UI supplies them. Export uses the same filters but not page number. CSV cells with spreadsheet-formula prefixes are escaped. Analytics accepts `period=1h|24h|7d|30d|custom`; custom uses `start` and `end` in UTC, bounded to 31 days.

### WAF integration and management semantics

The existing implementation had security events, signature blocking, rate
limiting and in-memory failed-login tracking, but no separate Phase 5
alert/IP-management models. The shared `waf/management/store.py` now reads and
writes those management records through PostgreSQL in the active Supabase setup,
while retaining SQLite compatibility for disposable tests.

Each WAF request synchronizes persisted rule/detector/runtime overrides and queued unblock commands. Individual toggles affect actual matching, including specialized brute-force and upload rules. JSON files remain the built-in definitions; database states override enabled flags and managed rule settings. Changing a detector's enabled state does not rewrite its individual rule states.

- Blacklisted IPs receive 403 before normal request inspection.
- Manual temporary IP policies cover all proxied paths and return 429 until expiry. Duration is 1 second to 7 days.
- Backend-confirmed brute-force threshold events create login-scoped temporary policies. Other pages remain usable unless another policy blocks them.
- Unblock removes the selected temporary policy and queues a reset of associated in-memory login counters; the next WAF request consumes it. A separate blacklist must be removed separately.
- Whitelist NORMAL is informational and retains all inspection. RATE_LIMIT_BYPASS and BLACKLIST_BYPASS skip only their named guard. Explicitly confirmed FULL_BYPASS skips detection/policy blocking, but never hard size/transport limits; it is not the default.
- HIGH/CRITICAL matched detections generate one alert per event. Acknowledging an alert does not remove its event or disable protection.

System Status reads the authenticated WAF `GET /internal/status` endpoint. It requires a loopback peer and a shared random bearer token; the dashboard obtains that token server-side from the database. The token is never sent to the browser. This reads the actual WAF limiter and failed-login state, not a dashboard-side imitation. Status is cached for three seconds. An unavailable WAF is shown as offline/unknown, never falsely online.

New tables: `management_settings`, `rule_states`, `detector_states`, `ip_policies`, `management_commands`, `security_alerts`, `event_categories`, `management_audit`, `dashboard_admins`, `admin_login_limits`. Existing event history is preserved. Category and alert projections are backfilled incrementally on startup; new event/projection/alert writes share one transaction. SQLite WAL mode, indexes, bounded pagination, connection cleanup and a busy timeout support the two local services.

### Administrator security and configuration

Passwords are hashed with Werkzeug. Login failures are rate-limited independently of storefront logins. The signed administrator cookie is named `waf_admin_session`, has HttpOnly/SameSite=Strict protection and a 30-minute session lifetime. CSRF checks cover login, logout and management mutations. API input is validated, SQL values are parameterized, and event-derived text is escaped in templates and inserted with `textContent` in JavaScript. A self-only CSP prevents untrusted scripts from running in the dashboard.

The proxy strips `waf_admin_session` before forwarding cookies to the target. Ports are not cookie-isolation boundaries: do not treat a deliberately vulnerable application on the same hostname as a production-safe neighbor. Use a separate browser profile for deliberate XSS demonstrations and restrict local filesystem access to the security database, which contains administrator hashes and management secrets.

Optional environment variables (defaults are sufficient):

- `DASHBOARD_PORT=9000`, `DASHBOARD_HOST=127.0.0.1`.
- `DASHBOARD_WAF_URL=http://127.0.0.1:8080` (loopback management destinations only).
- `WAF_DATABASE_PATH`: dashboard shared database override; configure the WAF's `DATABASE_PATH` override consistently when embedding its factory. CLI defaults already share the same file.
- `DASHBOARD_HTTPS=true`: Secure cookies when an independently configured local HTTPS endpoint is actually in use; do not enable for the default HTTP demonstration.
- `DASHBOARD_ADMIN_USERNAME` / `DASHBOARD_ADMIN_PASSWORD`: optional startup provisioning of a new account. Prefer the interactive setup command to avoid plaintext credentials in shell history. Existing accounts are not overwritten.

### Full verification and demonstration

Run the suites separately because the WAF retains its existing flat module imports:

```powershell
cd D:\NISec\waf
..\.venv\Scripts\python.exe -m pytest -q
cd D:\NISec
.\.venv\Scripts\python.exe -m pytest admin_dashboard/tests -q -s
.\.venv\Scripts\python.exe -m pytest lab_tests -q
```

SQLite-era final verification on 2026-09-10:
**99 WAF tests + 19 dashboard tests + 5 lab tests = 123 passing tests**. After
the Supabase migration, the dashboard suite also includes PostgreSQL integration
coverage. The three-service integration test supports ports **5000, 8080,
9000**; if occupied, it selects temporary ports and reports them. Test
databases/uploads are temporary; controls are exercised against test-owned
services, not your running demonstration database.

Dashboard coverage includes authentication/session/CSRF enforcement, safe rendering and exports, malformed input, real counts, pagination/filters, rule/detector state persistence, alerts, policy validation and truthful offline status. The real TCP integration test verifies legitimate ALLOW traffic, all six attack categories, 403/429 responses, alerts, temporary blocks, unblock/login recovery, blacklist/whitelist behavior, actual rule/detector enforcement changes, JSON/CSV export, timeline data and the locally served chart library.

Browser verification: signed in to the actual dashboard on 9000, inspected desktop styling and rendered charts, and confirmed System Status showed all three services online and the database healthy. A real `tote` search through 8080 and its assets increased total requests from 98 to 102 and allowed requests from 89 to 93 without reloading the dashboard; the traffic chart updated too. No dashboard console errors or warnings were observed. Storefront styling through the WAF also rendered correctly. Mobile CSS breakpoints are implemented, but the browser's requested 390px viewport override remained at 1265px, so mobile visual verification remains manual.

For your presentation:

1. Start all three services using the commands at the top of this guide. Open the storefront on 8080 and the authenticated dashboard on 9000.
2. Search for `tote` in the storefront. Within a polling cycle, find the new ALLOW event and updated totals on the dashboard.
3. Use the controlled Phase 4 examples above. Check the category chart, recent events and alert counter, then open an incident to view redacted evidence.
4. For brute force, use five wrong storefront logins followed by a sixth request. Find the temporary login block in IP Management and remove it to demonstrate recovery.
5. In an isolated test session, temporarily blacklist the test source IP and confirm a 403 on the storefront, then remove the policy. Whitelisting with NORMAL should not allow attack syntax through.
6. Use Security Rules to disable and re-enable one rule and verify its effect with the corresponding controlled sample. Restore all intended rule states afterward. Multiple matching rules may still block a sample when only one is disabled.
7. Filter Security Events, export CSV/JSON, acknowledge an alert, and show System Status with backend and WAF online.

### Files added and integration changes

The initial dashboard implementation added `admin_dashboard/` with the app/config/setup command, requirements, service modules, Jinja templates, responsive CSS, polling/chart JavaScript, local Chart.js assets/license, and unit/live tests. Added `waf/management/` for shared management persistence. The completion report above lists subsequent Phase 6–18 additions.

Modified WAF integration points: `waf/app.py`, `waf/database/models.py`, `waf/engine/rule_engine.py`, `waf/engine/detector.py`, `waf/engine/rate_limit.py`, `waf/detectors/brute_force_detector.py`, and `waf/proxy.py`. Extended `waf/tests/live_service.py` to start the dashboard for three-process validation. Updated this combined guide; no new duplicate README was created.

### Operational limitations and troubleshooting

This remains a single-machine, single-WAF-process academic demonstration, not a production WAF. In-memory rate/login counters reset on restart, whereas PostgreSQL policies/alerts/toggles persist. Multiple workers need coordinated counters and command handling. Historical events, alerts and audit entries have no retention scheduler. Large databases may need precomputed aggregates and retention instead of frequent live SQL aggregation.

Public GeoIP lookup requires an optional local City database and reader; unknown/private locations remain unplotted. File detection is not antivirus scanning. Trust bypasses must be selected deliberately; NORMAL remains the default. Exports stop at 10,000 matching records; narrow the filters for larger histories. ADMIN/VIEWER authorization is implemented, but there is no password-reset UI, MFA or TLS server. Use only on a controlled local machine. Kali VM execution and manual mobile viewport verification remain pending; measured effectiveness is limited to the documented synthetic dataset.

If a page cannot connect, check that its terminal is still running and that the port is free. If System Status says management unavailable, restart the WAF with the updated `waf/app.py` and ensure both processes share the same database. If port 8080 looks unstyled, restart the WAF and hard-refresh the browser: its Flask app must have `static_folder=None` so storefront CSS/JS are proxied. Dashboard CSS and Chart.js are served by the dashboard itself on 9000. No Internet connection is needed for those assets.
