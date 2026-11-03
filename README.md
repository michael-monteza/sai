# SAIP: Shadow AI Platform

Find out which AI services your people really use, decide which are approved, and keep the evidence for ISO/IEC 42001.

SAIP is a multi-company web console (PHP / MariaDB) plus a small Windows collector. The collector reads **Sysmon DNS events** on workstations, keeps only hostnames that match your AI registry, and sends them to the console. The console turns that into an AI inventory, shadow-AI alerts, risk scores, department adoption, reports and an audit trail.

> It shows *who looked up which AI service and when*. It does not read page content, prompts, passwords or Windows user names, and it does not block anything.

## Contents
1. [Features](#features) 2. [How it works](#how-it-works) 3. [Requirements](#requirements) 4. [Install the server](#install-the-server) 5. [First steps in the console](#first-steps-in-the-console) 6. [Install the collector on workstations](#install-the-collector-on-workstations) 7. [Upgrade](#upgrade) 8. [Operations](#operations) 9. [Security](#security) 10. [Development and tests](#development-and-tests) 11. [Troubleshooting](#troubleshooting) 12. [Repository layout](#repository-layout)

More documentation: **[AdminGuide-README.md](AdminGuide-README.md)** (production go-live checklist, backups, scheduled jobs) and **[docs/REFERENCE.md](docs/REFERENCE.md)** (API, RBAC, SIEM/webhooks, Sysmon reference). The in-app **Getting Started** page repeats the collector steps.

---

## Features

- **Multi-company**: every customer (tenant) has its own registry, workstations, events, users and enrollment key.
- **AI inventory and registry**: services and DNS names with registrar, purpose, category, data class and risk; ships with the Top-100 AI services and about 54 well-known ones. Inventory shows what was *detected* or added by hand; the full registry is managed separately.
- **Discovery**: unknown AI-looking domains seen on workstations, ready to classify or exclude.
- **Workstations and events**: per-computer history, per-service workstation lists, searchable, filterable, server-paged event log, local-time display.
- **Governance**: sanction / review / block decisions, policies, access-request queue, ISO 42001 control assessment and score.
- **Reports and exports**: sanctioned vs unsanctioned trend, department adoption, coverage; CSV and XLSX.
- **Integrations**: Google sign-in, SIEM/webhooks (HMAC-signed JSON, CEF, Splunk HEC, syslog), pull API with bearer tokens.
- **Security**: RBAC (super_admin, it_admin, auditor, viewer), Argon2id, lockout, CSRF, CSP, tenant scoping, append-only audit log, least-privilege database account.
- **Web installer and upgrader**: extract, browse to `/install.php`, done.

## How it works

```
 Workstation (Windows)                              Server (PHP + MariaDB)
 ┌──────────────────────────────┐   HTTPS / JSON   ┌───────────────────────────────┐
 │ Sysmon  (DNS event ID 22)    │                  │ /api/v1/events/ingest         │
 │   ↓                          │  ───────────────▶│ match against registry        │
 │ Collect-AiUsage.ps1 (5 min)  │                  │ inventory · risk · reports    │
 │  · downloads rules from SAIP │ ◀─────────────── │ Console (Slim 4 + Bootstrap)  │
 │  · caches + spools offline   │   rules/config   │ SIEM · webhooks · audit       │
 └──────────────────────────────┘                  └───────────────────────────────┘
```
Chrome, Edge, Brave and Firefox can bypass the Windows DNS client that Sysmon watches. The installer therefore sets browser machine policies (built-in resolver and DNS-over-HTTPS off) so their lookups become visible. They are reversible with the uninstaller.

## Requirements

| | |
|---|---|
| Server | PHP **8.2+** (`pdo_mysql`, `sodium`, `mbstring`, `openssl`, `curl`), MariaDB 10.6+ / MySQL 8, Apache 2.4 with `mod_rewrite` + `mod_headers` (XAMPP works), Composer (only when installing from source) |
| Workstations | Windows 10/11 or Server 2016+, PowerShell 5.1+, local Administrator once, network access to the server, internet to `live.sysinternals.com` (or copy `Sysmon64.exe` beside the scripts) |
| Network | Workstations must reach the server address. Use HTTPS in production |

---

## Install the server

### Option A: web installer (recommended)

1. **Get the code.** Either download a release package, or build one from source:
   ```bash
   git clone <this-repo-url> saip && cd saip
   composer install --no-dev --optimize-autoloader
   php tools/make-release.php          # creates dist/saip-<version>.zip (includes vendor/)
   ```
   You can also use the cloned folder directly after `composer install`.
2. **Extract** the package into your web folder (XAMPP: `C:\xampp\htdocs\saip`; Ubuntu: `/var/www/html/saip`). On Linux make `config/` writable by the web user: `sudo chown -R www-data:www-data config`.
3. **Browse to** `http://your-server/saip/install.php` (any page redirects there until installed).
4. Follow the wizard:
   | Step | What you enter |
   |---|---|
   | Requirements | nothing; fix anything marked MISSING |
   | Site | the address people will use (pre-filled), environment, optional trusted proxy IPs |
   | Database | host/port/name and either an **administrator login** (the wizard creates the database and a restricted `saip_app` account; the login is not stored) or an existing database account. **Test connection** checks it |
   | Data | **Fresh install**, **Fresh with demo data**, or **Use existing data** (migrate an earlier install; nothing is deleted) |
   | Company and admin | company name, first platform administrator and password |
5. Copy the **collector enrollment key** shown once on the last page, then sign in.

The wizard writes `config/config.php` and `config/app.key`, creates all tables and migrations, applies least-privilege grants, optionally loads the AI registry or demo data, and locks itself. *While it is open anyone who can reach the URL can run it: install on a private network or restrict it by IP until it finishes.*

### Option B: command line

```bash
cp config/config.example.php config/config.php        # edit database settings, env=production
mysql -u root -p -e "CREATE DATABASE saip CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
mysql -u root -p saip < sql/schema.sql
mysql -u root -p saip < sql/catalog_seed.sql
php tools/migrate.php
php tools/provision-tenant.php "Your Company" yourslug       # prints the enrollment key once
php tools/create-admin.php admin "<12+ char password>" super_admin
php tools/load-top100.php yourslug                           # optional registry
php tools/load-known-ai.php yourslug
php tools/db-grants.php saip_app                             # optional least-privilege account
echo '{"version":"'$(cat VERSION)'"}' > config/installed.lock
```

### Apache

Enable `mod_rewrite` and `mod_headers` and allow overrides (`AllowOverride All`); the shipped `.htaccess` sends everything to `index.php` and blocks `app/ config/ sql/ tools/ vendor/` and `.md/.sql/.log` files. Verify `/config/config.php` and `/composer.json` return 404/403. For production serve HTTPS and read [AdminGuide-README.md](AdminGuide-README.md).

### Demo data

Choose *Fresh install with demo data* in the wizard, or run `php tools/loaddemodata.php <slug>`. Remove it later with `php tools/cleandemo.php <slug> --demo-only --yes` (or without `--demo-only` to clear **all** events and workstations while keeping the AI services and registry). Never load demo data in production.

---

## First steps in the console

1. Sign in with the administrator you created (change the password; create named users under **User Management**).
2. **AI Services & DNS Registry / Inventory**: review the loaded services and **Sanction** the tools your company allows. Anything detected and not sanctioned is reported as *Shadow*.
3. **Collectors & Monitoring** → **New enrollment key** (if you need another) and **Download collector package**.
4. Install the collector on a pilot workstation (next section), then **Authorize** it in Collectors & Monitoring.
5. Map computers to departments in **Workstations**; work through **ISO 42001 Readiness**.
6. Optional: Google sign-in (Administration → Authentication), SIEM/webhooks (Operations), retention (Settings).

---

## Install the collector on workstations

**Get the package.** In the console open **Collectors & Monitoring → Download collector package**: `SaipCollector.zip` containing the scripts, the Sysmon configurations and `collector.config.json` already pointing at your server. (From source: the `collector/` folder is the same content.) You also need the **enrollment key** (shown once when it was created; create a new one under Collectors & Monitoring if needed).

**On each target workstation:**

1. Copy `SaipCollector.zip` to the PC, right-click → **Extract All** (for example to `C:\Temp\SaipCollector`).
2. Open **PowerShell as Administrator** and go to that folder:
   ```powershell
   cd C:\Temp\SaipCollector
   Set-ExecutionPolicy -Scope Process Bypass -Force
   .\Install-Collector.ps1 -ServerUrl https://your-server/saip/api/v1 -EnrollmentKey enr_xxxxxxxxxxxx
   ```
   Use the address workstations can reach (not `localhost`). For a lab with plain `http://` add `-AllowInsecureHttp`.
3. The installer is hands-off and prints an **OK / ATTENTION** summary. It:
   1. copies the collector to `C:\Tools\SaipCollector` (an existing `collector.config.json` is kept on re-runs),
   2. writes and locks down the configuration,
   3. checks the server is reachable,
   4. installs or repairs **Sysmon** and proves it logs DNS with a test lookup,
   5. sets the browser machine policies so Chrome/Edge/Brave/Firefox lookups are visible,
   6. enrolls the PC and runs the collector once,
   7. schedules `SAIP-AI-Usage-Collector` every 5 minutes as SYSTEM.
4. In the console, **Collectors & Monitoring → Authorize** the PC (status Pending → Authorized). The workstation then appears under **Workstations** within minutes.
5. **Verify** on the PC (browse to an AI site first, then):
   ```powershell
   C:\Tools\SaipCollector\Show-SysmonDns.ps1 -Match 'chrome|msedge' -Minutes 10
   ```
   Browser lookups should be listed. Browsers pick up the policy at their **next start** (fully quit and reopen; `-RestartBrowsers` does it for you but loses unsaved browser work).

**Installer options**

| Option | Meaning |
|---|---|
| `-InstallDir` | default `C:\Tools\SaipCollector` |
| `-IntervalMinutes` | how often it runs (default 5) |
| `-EnableNetwork` | also log outbound HTTPS connections (Sysmon event 3) for services on dedicated IPs; ChatGPT/Gemini sit on shared CDNs and are detected by DNS only |
| `-SkipSysmon` | Sysmon already installed |
| `-SkipBrowserPolicy` | leave browser settings alone (browsers using their own resolver will then be invisible) |
| `-RestartBrowsers` | close open browsers so the policy applies now |
| `-AllowInsecureHttp` | allow plain http (lab only) |

**Roll out to many PCs.** Use the same command from a GPO startup script, Intune or SCCM running as SYSTEM, or PowerShell remoting:
```powershell
$pcs = 'PC01','PC02'
foreach ($pc in $pcs) {
  Copy-Item .\SaipCollector -Destination "\\$pc\C$\Temp\" -Recurse -Force
  Invoke-Command -ComputerName $pc -ScriptBlock {
    Set-ExecutionPolicy -Scope Process Bypass -Force
    & C:\Temp\SaipCollector\Install-Collector.ps1 -ServerUrl 'https://your-server/saip/api/v1' -EnrollmentKey 'enr_xxxx'
  }
}
```
Always pilot on one or two machines first. Authorize collectors in the console (or set `auto_authorize` only in a lab).

**Update:** run `Install-Collector.ps1` again from a newer package (settings are kept). **Remove:** `C:\Tools\SaipCollector\Uninstall-Collector.ps1 [-RemoveSysmon] [-RemoveData]`; it restores the browser policies it changed.

**Collector troubleshooting**

| Symptom | Fix |
|---|---|
| Nothing appears in SAIP | PC still *Pending*: authorize it. Check `serverUrl` is not the placeholder or `localhost`; firewall; `C:\ProgramData\SaipCollector\collector-error.log` |
| "ServerUrl is not set" | pass `-ServerUrl` or edit `collector.config.json` in the folder you run from |
| Sysmon error 32 / file in use | restart Windows and run the installer again (it self-repairs) |
| Browser lookups missing | restart the browser; check `edge://policy` / `chrome://policy` are not overridden by another tool |
| Execution policy error | `Set-ExecutionPolicy -Scope Process Bypass -Force` in the same window |
| ChatGPT/Gemini not on network view | expected: shared CDN addresses; DNS detection is used |

---

## Upgrade

Extract the new release over the old folder **keeping `config/`** (the package contains no config or key), then browse to the site. Because the files are newer than the database, it redirects to `install.php`, which lists the pending migrations; sign in as a super_admin, tick the backup box and click **Upgrade now**. Collectors receive a temporary 503 and retry. Releases add numbered, reversible migrations in `sql/migrations`, so any older install upgrades straight to the newest. CLI: `php tools/migrate.php`. Details in [AdminGuide-README.md](AdminGuide-README.md).

## Operations

| Task | Command |
|---|---|
| Retention purge (daily) | `php tools/purge.php [--dry-run]` |
| SIEM/webhook retries (every few minutes) | `php tools/dispatch-integrations.php` |
| IP ownership map (weekly) | `php tools/refresh-ip-map.php` |
| Add a company | Companies → *Add company*, or `php tools/provision-tenant.php "Name" slug` |
| Reset/clean test data | `php tools/cleandemo.php <slug> [--demo-only] [--yes]` |
| Build a package | `php tools/make-release.php` |

**Back up** the database, `config/config.php` and `config/app.key` (store the key apart from database dumps; it encrypts Google and webhook secrets).

## Security

OWASP-aligned: deny-by-default RBAC, tenant scoping on every query, prepared statements only, CSRF token + Origin check, strict CSP and security headers, Argon2id with lockout and rate limits, `__Host-` HTTPS cookies, secrets encrypted with libsodium, SSRF guard on outbound integrations, formula-injection-safe exports, append-only audit log, least-privilege DB account. Production checklist: HTTPS, `env=production`, `auto_authorize=false`, restricted DB account, delete `config/initial-admin.txt` if present, protect `install.php`. See [AdminGuide-README.md](AdminGuide-README.md) §1 and §10. Report vulnerabilities privately to the maintainers rather than opening a public issue.

## Development and tests

```bash
composer install
php -S 127.0.0.1:8099 index.php          # quick local server (or use XAMPP/Apache)
php tests/run.php                        # regression + security suite (writes test data: use a dev database)
php -l app/Kernel.php                    # lint any file
```
The suite covers ingest, RBAC, tenant isolation, CSRF, injection and audit behaviour. Run it against a development copy, never production.

## Troubleshooting (server)

| Symptom | Check |
|---|---|
| Redirected to `install.php` | not installed, or files newer than the database (upgrade page) |
| `{"error":{"code":"server_error"...}}` | the request id is in the PHP/Apache error log (`[SAIP <id>]`) with the real cause |
| 404 on every page | `mod_rewrite` / `AllowOverride All`, correct sub-path |
| Cannot sign in after enabling HTTPS | clear cookies (name becomes `__Host-saip_sid`); make sure PHP sees HTTPS behind a proxy (`trusted_proxies`) |
| Google "state mismatch" | redirect URI in Google Cloud must match exactly; correct server clock; user's email exists in SAIP |
| Secrets cannot be decrypted | `config/app.key` differs from the one used when they were saved |

## Repository layout

```
index.php            front controller (Slim 4) and install/upgrade gate
install.php          web installer and upgrader
VERSION              release version (compared with config/installed.lock)
app/                 Kernel, Modules/*Module.php, Middleware, Security, domain services, Installer
assets/              console UI (grid, registry, reports, admin, integrations)
config/              config.example.php, rbac.php (instance files are git-ignored)
collector/           Windows collector, Sysmon installer and configs, uninstaller
sql/                 schema.sql, catalog_seed.sql, migrations/, AI service data
tools/               CLI: migrate, create-admin, load-*, cleandemo, purge, make-release ...
tests/               run.php (server suite), Test-Ingest.ps1
docs/REFERENCE.md    API, RBAC, SIEM/webhooks, Sysmon reference
AdminGuide-README.md production go-live and administration guide
```

## Licence

No licence has been chosen yet. Add a `LICENSE` file before publishing publicly.
