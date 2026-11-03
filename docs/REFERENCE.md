# SAIP – Shadow AI Platform (multi-company)

Discovery, governance and ISO/IEC 42001 readiness for shadow AI. **One platform, many companies**: each company (tenant) has its own AI register, collectors, telemetry, policies, request queue, ISO 42001 control register, audit log and users. Reporting only: SAIP never blocks traffic (the former DNS blocklist feed was removed; the platform is reporting-only) and never collects prompts, page content, credentials, keystrokes or Windows usernames.

## Architecture (Slim 4)

```
index.php               front controller (Slim); serves from a sub-folder (XAMPP) or as web root
app/Kernel.php          middleware stack + one registration call per module
app/Modules/*Module.php one class per area: routes, per-route permissions, handlers
app/Middleware/         RequestContext, SecurityHeaders, ConsoleSession (auth + CSRF), RequirePermission (RBAC), CollectorAuth
app/Security/           Rbac (permission matrix lookup), Auth (sessions, lockout, password policy)
app/*.php               domain services: Db, Audit, Risk, Iso, Adoption, DomainRegistry, Reports, Xlsx, Tenants, ServiceRepo
app/Views/              shell + login templates (menu filtered by permission)
config/rbac.php         roles and permissions (edit here to change who can do what)
assets/                 ui.js (modals, forms), grid.js (DataGrid), registry.js, reports.js, admin.js, app.js
sql/migrations/         numbered, reversible (tools/migrate.php)
```
Install dependencies once with `composer install`. The API paths (`/api/v1/...`) are unchanged, so existing collectors keep working.

## Google sign-in, SIEM & webhooks, Sysmon reference

**Google Sign-In** (Administration -> Authentication, platform administrators only). OpenID Connect authorization-code flow with PKCE, state and nonce; the ID token comes straight from Google's token endpoint over TLS and its issuer, audience, expiry, nonce, verified email and optional Workspace domain are checked. Accounts are matched by Google subject, then by verified email; optionally create them automatically for allowed domains (default role + company). Password sign-in ("internally") stays available unless a user is set to Google-only in User Management. The client secret is encrypted at rest (libsodium; key in `config/app.key` or env `SAIP_APP_KEY`). Register the redirect URI shown on the page (`.../auth/google/callback`) in Google Cloud Console.

**SIEM & webhooks** (Operations -> SIEM & Webhooks, `integrations.*`). Destinations: signed HTTPS webhooks (JSON, or CEF), Splunk HTTP Event Collector, and syslog (UDP/TCP, RFC 5424, CEF or JSON). Event types: `audit.event`, `shadow_ai.detected` (an unsanctioned service seen on a workstation for the first time), `discovery.new_domain`, and the optional raw `usage.event` stream. Events go to an outbox and a worker delivers them with cursors, retries and exponential back-off, so an outage loses nothing: schedule `php tools\dispatch-integrations.php` every minute (`schtasks /Create /SC MINUTE /MO 1 /TN "SAIP integrations" /TR "php C:\xampp\htdocs\2026\saip\tools\dispatch-integrations.php"`). Webhooks carry `X-SAIP-Timestamp` and `X-SAIP-Signature: sha256=HMAC(secret, timestamp + "." + body)`. Destinations must be public https URLs (SSRF guard; private addresses only when `integrations.allow_private` is true). SIEMs can instead **pull** with an API token: `GET /api/v1/siem/events?since_id=N&types=...&format=json|jsonl|cef` and `/api/v1/siem/usage` (`Authorization: Bearer saip_siem_...`).

**Sysmon capabilities** (Collectors & Monitoring -> Sysmon capabilities): the Sysmon events SAIP collects (22 DNS, optional 3 network) and deliberately does not (1, 5, 7, 11-15, 23, 25, 26 ...), sample raw XML and the JSON sent to SAIP, the field mapping, and a configuration builder that downloads a `sysmon-config.xml` logging only what SAIP uses.

**Browsers that bypass Windows DNS.** Sysmon DNS (EID 22) misses Chrome/Edge when they use their built-in resolver or DNS-over-HTTPS. Network connections (EID 3, `Install-Sysmon.ps1 -EnableNetwork`, then "Network connections" in Monitoring options) see the connection itself with no browser change. A connection is matched by host name when Sysmon has one, otherwise by the destination address of a registered service (`ip_map`, built by `tools\\refresh-ip-map.php`: schedule it hourly). Only dedicated addresses count: CDN / shared addresses (`config/shared_ip_ranges.php`, plus reverse-DNS checks) are ignored and reported as `ambiguous`, so services hosted on shared infrastructure such as ChatGPT (Cloudflare) and Gemini (Google) are not detected this way. `Install-Collector.ps1` now does this by default (machine policies `BuiltInDnsClientEnabled=0`, `DnsOverHttpsMode=off` for Chrome/Edge/Brave and DNS-over-HTTPS off for Firefox; previous values saved and restored by `Uninstall-Collector.ps1`); `-SkipBrowserPolicy` opts out and `-RestartBrowsers` applies it immediately. The installer also verifies Sysmon DNS logging with a test lookup and repairs it if needed, and prints a pass/fail summary.

**Event log paging.** The event log (service and workstation views) searches, filters, sorts and pages on the server, so very large logs stay fast; CSV export honours the current search/filters (up to 50,000 rows).

## Roles & permissions (RBAC)

Permissions are `area.action` (`registry.write`, `inventory.delete`, `audit.read`, ...). Roles (`config/rbac.php`): **super_admin** (everything, all companies), **it_admin** (everything in own company incl. user management, no company management), **auditor** (read everything + audit log, no changes), **viewer** (read-only, no audit log or users). Every API route is guarded by `RequirePermission`; the menu and buttons only hide what the API would refuse anyway. Denials are audited (`access_denied`). User management: an it_admin manages users of their own company and cannot assign a role above their own; nobody can deactivate/delete themselves; the last active platform administrator is protected; password resets end that user's other sessions.

## Security (OWASP ASVS / Top 10)

| Area | Controls |
|---|---|
| A01 Access control | deny-by-default per-route permissions; every query tenant-scoped; ids validated; IDOR returns 404 across companies |
| A02 Crypto | Argon2id password hashes (rehash on sign-in); collector keys stored as SHA-256; random 256-bit keys; HTTPS-aware cookies + HSTS; optional DB TLS (`db.ssl_ca`) |
| A03 Injection | PDO real prepared statements (emulation off) everywhere, strict `sql_mode`; column names allow-listed (no mass assignment); output escaped in the UI; CSV/Excel formula injection neutralised |
| A04/A05 Design & config | CSP without inline script, `X-Frame-Options`, `nosniff`, `Referrer-Policy`, COOP/CORP, no-store caching; generic errors with request ids (details only in the server log); `.htaccess` blocks app/config/sql/tools/vendor; `auto_authorize` defaults to false |
| A07 Authentication | session id regenerated at sign-in, `__Host-` cookie over HTTPS, HttpOnly + SameSite=Strict, idle (60 min) and absolute (12 h) timeouts; lockout after 5 failures (15 min); per-IP rate limit; password policy (12+ chars, 3 of 4 classes, not the username); password change/reset invalidates older sessions |
| CSRF | synchronizer token (`X-CSRF-Token`, constant-time compare) on every state-changing API call **plus** same-origin `Origin`/`Referer` check, JSON-only bodies, SameSite=Strict; login and logout forms carry their own token |
| A08/A09 Integrity & logging | append-only audit trail with actor, action, record, before/after values, client IP and request id; exports, denials, CSRF failures, logins and lockouts are logged; `sql/db-least-privilege.sql` + `tools/db-grants.php` give the app a DML-only account that can only INSERT/SELECT `audit_logs` |
| A06 Components | two runtime dependencies (slim/slim, slim/psr7), versions locked by `composer.lock`; run `composer audit` |

Production checklist: serve over HTTPS; create the least-privilege accounts; set `auto_authorize` false; keep `config/config.php` out of the web root or protected (`.htaccess` does this); schedule `tools/purge.php`; back up the database.

## What is in the console (`/`)

| Mockup feature | Where | Notes |
|---|---|---|
| Executive dashboard (KPIs, trend, risk donut, shadow alerts) | Executive Dashboard | live from the database |
| AI asset inventory, filters, register system, CSV export, governance record (owner, purpose, lifecycle, domains) | AI Fleet Inventory | cl. 8.2 documentation |
| 4-quadrant matrix + risk engine | Risk Matrix & Engine | score = 30% data class, 20% training exposure, 20% vendor, 15% identity, 15% observed usage |
| Policies + access-request queue (approve → sanctioned) | Governance & Requests | |
| ISO 42001 readiness: control register, compliant/not, evidence, tier, report, evidence JSON | ISO 42001 Readiness Hub | compliant requires recorded evidence; every change audit-logged |
| AI Services & DNS Registry | AI Services & DNS Registry | classification Sanctioned / Unsanctioned / Under Review / Excluded; per-domain type and Exact vs Subdomain matching; archive instead of delete; before/after change history; every change bumps the config version collectors sync to |
| FQDNs & registrars | AI Services & DNS Registry (second tab) | every registered hostname with service, root domain, DNS registrar, functional purpose and category; add/edit/delete in modals, bulk activate/deactivate/delete, CSV import (Service Name, FQDN / Endpoint, Root Domain / Site, DNS Registrar / Registry, Functional Purpose & Role, Primary Category) with validate-first |
| Domain Discovery | Domain Discovery | New → Under review → Classified / Excluded workflow with per-workstation hits; classifying adds the domain to the registry |
| Adoption analytics: None/Low/Moderate/High per workstation, department comparison, weekly/monthly trend, enablement list, CSV, configurable thresholds | AI Adoption | score = active days 40 + AI services 20 + event frequency 25 + sanctioned-service activity 15; targets and Low/High cut-offs editable per company; framed as training opportunities, not employee evaluation |
| Telemetry sources | Collectors, Workstations, Discovery Review | Sysmon collectors replace the mock "agent hits" |
| User management, companies, audit log | User Management, Companies, Audit Log | RBAC roles super_admin / it_admin / auditor / viewer; add/edit/delete users in modals; audit viewer with filters, before/after diff and CSV export |

Mock items intentionally **not** reproduced as fake data: "Simulate Shadow AI Event", the M365 / SIEM "connected" badges, "data exposure events" (SAIP cannot see uploads/prompts), "Prompted or uploaded" counts, and pre-claimed compliance. Planned connectors are not implemented.

## Multi-company model

* `tenants` row per customer; every data table carries `tenant_id`; every console query is scoped to the current tenant.
* Creating a company clones the AI catalogue (`catalog_*` tables), the 14 ISO 42001 controls (all **not compliant** until assessed) and default policies. All services start as Shadow until sanctioned.
* Collectors enrol with the company's **enrollment key** (shown once, stored hashed), then get an individual API key. A collector can only write to its own company.
* Platform super administrators have no company and switch via the header selector. IT admins / viewers are bound to one company.

## Install (Windows + XAMPP)

**Easiest:** extract the package, browse to `/install.php` and follow the wizard (requirements, site URL, database creation, fresh / demo / existing data, company and administrator). Upgrades: extract the new version over the old one and open the site; it sends you to the upgrade page. Build the package with `php tools\make-release.php`. The manual steps below are the equivalent command line.

```
C:\xampp\mysql\bin\mysql.exe -u root < sql\schema.sql
C:\xampp\mysql\bin\mysql.exe -u root saip < sql\catalog_seed.sql
composer install
php tools\migrate.php                                          # applies sql\migrations (registry, network events, discovery, collector health, RBAC/audit)
php tools\provision-tenant.php "Your Company" yourslug        # prints the collector enrollment key once
php tools\create-admin.php admin "<12+ char password>" super_admin        # roles: super_admin | it_admin | auditor | viewer
php tools\load-top100.php yourslug                          # loads the Top-100 AI services directory: services + FQDNs, DNS registrar, functional purpose (sql\top100_ai_services.php); safe to re-run
php tools\load-known-ai.php yourslug                        # loads ~54 well-known AI services (OpenAI/Anthropic APIs, Grok, Mistral, Cursor, ElevenLabs, ...) as Unsanctioned; safe to re-run
php tools\seed-demo.php yourslug                              # OPTIONAL demo data; remove: --purge
```
Open `http://localhost/2026/saip/` (or your port-8080 vhost) and sign in. `config\config.php` holds DB credentials (copy of `config.example.php`; env vars `SAIP_DB_*` supported).

Add another customer: Companies → **Add company** (or `provision-tenant.php`), then create its users and give its enrollment key to whoever installs the collectors.

## Collectors (per workstation, elevated PowerShell)

Edit `collector\collector.config.json` (`serverUrl`, `enrollmentKey`), then `.\Install-Sysmon.ps1` and `.\Register-ScheduledTask.ps1 -IntervalMinutes 5`. The first run registers the machine; authorize it in **Collectors & Monitoring** (or set `auto_authorize` in config for a lab). **The collector (v2.0.0) contains no domain list**: it pulls the registry and monitoring options from `GET /collector/config`, caches them in `config-cache.json`, and re-syncs when the config version changes. With no config ever fetched it collects nothing. If the server is down, batches are buffered in `<dataDir>\spool` and replayed in order. Hostnames not in the registry are reported for Domain Discovery only if they contain a server-supplied hint keyword (Collectors & Monitoring → Monitoring options). Event ID 3 (network connections) is optional: enable it in the console and uncomment the block in `sysmon-config.xml`. Event IDs 1 and 5 are not collected. v1.0.0 collectors keep working through `GET /collector/domains`.

Sysmon limitations (DNS ≠ session, cached/DoH lookups missed, no content/user/duration, shared domains excluded, Windows endpoints only) are unchanged: see the notes in the UI banners. Counts are *observed DNS events*.

## API

Collector endpoints (`X-Collector-Id` + `X-Api-Key`; registration uses `X-Enrollment-Key`): `POST /api/v1/collector/register`, `POST /api/v1/events/ingest`, `POST /api/v1/collector/heartbeat`, `GET /api/v1/collector/config[?since=N]` (central rules + monitoring options; `GET /collector/domains` remains for v1.0.0 collectors). Console endpoints `/api/v1/console/*` use the browser session and an `X-CSRF-Token` header on writes. Errors: `{"error":{"code","message","details?"},"request_id"}`; 401/403/404/405/409/413/415/422/429/500.

Reporting (any signed-in role): `GET /console/dashboard/summary?days=N` (totals, sanctioned vs unsanctioned trend, coverage, limitations), `GET /console/reports` (catalog), `GET /console/reports/{name}?days=N&format=json|csv|xlsx` with names `usage-by-service`, `sanctioned-vs-unsanctioned`, `top-domains`, `network-activity`, `workstation-activity`, `discovery`, `collector-health`, `registry`. Exports are audit-logged; CSV cells starting with `= + - @` are neutralised; `.xlsx` is written without the PHP zip extension. `GET/POST /console/retention` reads/saves retention days (UI: Reports & Analytics).

Delete endpoints (IT admin; body `{ids:[...], preview?:true}`, `preview` returns the impact and changes nothing): `POST /console/services/delete` (service + its domains + its events), `POST /console/collectors/delete` (`data_only:true` clears collected events only; otherwise removes the collector, events, heartbeats, department mapping and discovery hits), `POST /console/registry/domains/delete` (a service keeps at least one domain), `POST /console/discovery/delete`. All are tenant-scoped, transactional and audit-logged; registry changes bump the config version.

Console tables share one component (`assets/grid.js`): search, per-column filters, sort, paging, row actions, multi-select bulk actions and CSV export of the filtered view.

Ingest example:
```
POST /api/v1/events/ingest   {"events":[{"sysmon_record_id":1001,"event_timestamp":"2026-10-30T09:15:02.123Z","query_domain":"claude.ai","process_image":"C:\\...\\chrome.exe","process_id":4242}]}
→ {"status":"ok","received":1,"accepted":1,"duplicates":0,"unmatched":0,"rejected":[]}
```
Limits: 1 MB body, 500 events/call, rate limits per IP and per collector, duplicate key `(collector_id, sysmon_record_id, event_timestamp)`.

## Maintenance

`php tools\migrate.php [status|down]` applies/lists/rolls back numbered migrations in `sql\migrations` (each has a `.down.sql`). `php tools\purge.php [--dry-run]` applies per-company retention (`retention_events_days`, `retention_discovery_days`, `retention_heartbeat_days` rows in `settings`; default keep events forever, heartbeats 90 days); schedule it daily.

## Testing

`php tests
un.php http://127.0.0.1:8080/2026/saip` runs the regression and security suite (sign-in, roles, CSRF, tenant isolation, registry rules, collector config, ingest, exclusion, reports and exports, input safety). It creates two throwaway companies and removes them afterwards; run it against a development database only.

`tests\Test-Ingest.ps1 -BaseUrl http://localhost/2026/saip/api/v1 -EnrollmentKey <company key>` registers a fake collector and checks accepted/duplicate/rejected/401 behaviour (it leaves a `WS-TEST-01` collector to delete).

## Security notes

Done: prepared statements, hashed collector and enrollment keys, per-collector authorization/rotation/revocation, bcrypt passwords, session cookies (HttpOnly, SameSite), CSRF on all console writes, role checks, tenant scoping, rate limits, size limits, CSV formula-injection guard, output escaping in the UI, audit log, `.htaccess` deny on `src/ config/ sql/ tools/`.
Before production: HTTPS (set `allowInsecureHttp=false`), `auto_authorize=false`, dedicated DB user instead of `root`, move the web root to a `public/` folder, never expose phpMyAdmin/MariaDB, delete `config/initial-admin.txt`.

## Not yet built

Hourly aggregation from the original brief, scheduled/CSV report variants beyond inventory, 2FA, SIEM/webhook connectors, M365 integration. `legacy/index-mockup.html` is the original static mockup.
