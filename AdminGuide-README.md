# SAIP Administrator Guide

Shadow AI Platform (SAIP): installation, production go-live checklist, daily operations and recovery.
Stack: PHP 8.2 or newer (developed on 8.4), MariaDB/MySQL, Apache (mod_rewrite, mod_headers), Slim 4, Sysmon + PowerShell collector on Windows workstations.

---

## 1. Read this first: production go-live notes

Do these **before** real users or workstations touch the system.

| # | Item | Why |
|---|------|-----|
| 1 | Set `'env' => 'production'` (or env var `SAIP_ENV=production`) in `config/config.php`. | Turns off development behaviour and verbose errors. |
| 2 | Serve over **HTTPS only** (valid certificate) and redirect HTTP to HTTPS. | Session cookies become `__Host-` + `Secure`; collectors send keys and data. Never run production on plain `http://`. |
| 3 | Set `'auto_authorize' => false`. | Each new workstation stays *Pending* until an administrator authorizes it. |
| 4 | Create a **least-privilege database account** and stop using `root`: `php tools\db-grants.php saip_app` (section 4). | Limits the damage of an application bug; makes `audit_logs` append-only. |
| 5 | **Delete `config/initial-admin.txt`** after first login and change that password. | It holds the first admin credentials in clear text. |
| 6 | **Back up `config/app.key` separately and securely.** | Encrypts stored secrets (Google client secret, webhook/SIEM tokens). If it is lost those secrets cannot be recovered and must be re-entered. If it leaks, rotate every stored secret. |
| 7 | Remove the unused folders `legacy/`, `legacy-v1/`, `sidebar-component.html` and `tests/` from the production server (keep `dist/` only if you want the zip on disk). | Smaller attack surface. `.htaccess` already blocks web access to `app config sql tools tests vendor legacy legacy-v1 src dist`, but do not rely on that alone. |
| 8 | Prefer an Apache document root where **only** `index.php` and `assets/` are public; otherwise keep the shipped `.htaccess` and confirm `AllowOverride All`. | See the lock-down check in section 3. |
| 9 | Set `trusted_proxies` only if SAIP sits behind a reverse proxy/load balancer; leave it empty otherwise. | Otherwise client IPs in audit/lockout can be spoofed via `X-Forwarded-For`. |
| 10 | Keep `integrations.allow_private` and `allow_http` **false**. | Blocks SSRF to internal addresses from webhooks/SIEM. Enable only for a named internal SIEM, knowingly. |
| 11 | Do **not** load demo data (`loaddemodata.php`) in production. If it was loaded: `php tools\cleandemo.php <slug> --demo-only --yes`. | Demo workstations/events pollute reports. |
| 12 | Create the scheduled jobs: retention purge, integration dispatcher, IP-map refresh, database backup (section 7). | Without them logs grow without limit and SIEM delivery is not retried. |
| 13 | Run `php tests\run.php` **against a staging copy**, never production. | The suite writes and removes data. |
| 14 | Keep the server and workstations on NTP. Times are stored in UTC and shown in each user's browser time zone. | Correct event ordering and reports. |

---

## 2. Requirements

- **Server:** PHP 8.2+ (8.2, 8.3 and 8.4 are supported) with `pdo_mysql`, `sodium`, `mbstring`, `openssl`, `curl`; MariaDB 10.6+ or MySQL 8; Apache 2.4 with `mod_rewrite` and `mod_headers`; Composer (build step only); outbound HTTPS if you use Google sign-in or SIEM/webhooks.
- **Workstations:** Windows 10/11 or Server 2016+, PowerShell 5.1+, local Administrator for installation, network access to the SAIP address.
- **Sizing:** each monitored workstation produces tens to a few thousand DNS events per day. Plan database disk accordingly and set retention (section 7).

---

## 3. Install on the production server (web installer)

1. **Get the package.** Build it once with `php tools/make-release.php` (creates `dist/saip-<version>.zip`, already containing `vendor/`; it never includes `config.php`, `app.key` or your data).
2. **Extract** it into the web folder (for example `/var/www/html/saip`). Make the `config/` folder writable by the web server user:
   `sudo chown -R www-data:www-data /var/www/html/saip/config` (you can tighten it again afterwards: `chmod 750 config`).
3. Make sure Apache has `mod_rewrite` and `mod_headers` and `AllowOverride All` for the folder, and that the site has a valid HTTPS certificate.
4. **Browse to `https://your-host/saip/install.php`.** (Any other page redirects there until installation is done.) The wizard has five steps:
   - **Requirements:** PHP version and extensions, `vendor/`, writable `config/`. Fix anything marked MISSING and reload.
   - **Site:** the address people will browse to (pre-filled; used for collector download links and Google sign-in), environment, optional trusted proxy IPs.
   - **Database:** either *create the database and a restricted application account for me* (enter a MySQL/MariaDB administrator login once; it is **not stored**), or *use a database and account I already created*. **Test connection** shows the server version and whether a SAIP database is already there.
   - **Data:** *Fresh install*, *Fresh install with demo data* (not for production), or *Use existing data (upgrade / migrate)* when the database already holds an earlier SAIP install. Nothing is erased unless you type the database name to confirm a fresh install over existing tables.
   - **Company and administrator:** company name and the first platform administrator (password policy enforced).
5. The wizard creates the database, tables, template catalogue and all migrations, applies least-privilege grants, writes `config/config.php` and `config/app.key`, creates the company and administrator, optionally loads the Top-100 and well-known AI registry (or demo data), and locks itself (`config/installed.lock`).
6. The last page shows the **collector enrollment key once**. Copy it. Then sign in.

**While the wizard is open anyone who can reach the URL can run it.** Install on a private network or restrict `install.php` by IP in Apache until it finishes. After the lock it only offers the upgrade page (which needs a super administrator login). Tick *Delete install.php* if you do not want even that.

Manual alternative (no browser): `config/config.example.php` to `config/config.php`, then the CLI tools (`php tools/migrate.php`, `provision-tenant.php`, `create-admin.php`, `load-top100.php`, `load-known-ai.php`, `db-grants.php`), and create `config/installed.lock` containing the JSON `{"version":"<contents of VERSION>"}`.

**What the wizard writes to `config/config.php`** (`env`, `base_url`, database host/port/name/user/password/`ssl_ca`, `auto_authorize=false`, `integrations` SSRF guard, `trusted_proxies`). It is mode 640; never commit it.

**Apache checklist**
- Virtual host with TLS; HSTS once HTTPS works everywhere: `Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"`.
- If SAIP is in a sub-path, the collector `serverUrl` must include it (the downloaded package already does, from the address you entered).
- Open the SAIP port in the firewall for workstation subnets only.

**Verify the lock-down.** Each of these must return 404/403, never content:
`/config/config.php`, `/config/app.key`, `/app/Kernel.php`, `/sql/schema.sql`, `/composer.json`, `/README.md`, `/AdminGuide-README.md`, `/tools/migrate.php`.

## 4. Database least privilege

The web installer does this for you when you choose *create the database and a restricted application account*. The commands below are for manual setups or to repair grants.

```
CREATE USER 'saip_app'@'localhost' IDENTIFIED BY '<long random password>';
GRANT SELECT, INSERT, UPDATE, DELETE ON saip.* TO 'saip_app'@'localhost';   -- temporary; db-grants narrows it
php tools\db-grants.php saip_app localhost        (run with the admin DB account configured)
```
Result: normal tables get select/insert/update/delete, `audit_logs` becomes **select + insert only** (append-only), `schema_migrations` is read-only, and the account cannot alter the schema.
Re-run `db-grants.php` after every upgrade that adds tables. Run `migrate.php` with the **admin** account, not `saip_app`.

---

## 5. First-day configuration (in the console)

1. **Sign in** as `admin`, change the password, delete `config/initial-admin.txt`.
2. **User Management**: create named accounts. Roles:
   - `super_admin`: platform owner (all companies, settings, integrations, user admin)
   - `it_admin`: full control of one company
   - `auditor`: reads everything including the audit log, changes nothing
   - `viewer`: dashboards and reports only

   Give each person the lowest role that works; avoid shared accounts. Accounts lock out after repeated failures.
3. **Companies**: add each customer. Each has its own enrollment key, data, users and registry; cross-company access is blocked by design.
4. **AI Services & DNS Registry** / **Inventory**: review the loaded services, **Sanction** the tools the company allows, set owners, data class and risk. Anything detected and not sanctioned is reported as Shadow AI.
5. **Settings, Google authentication** (if used): create an OAuth client in Google Cloud, set the redirect URI exactly as shown in the console (HTTPS), enter the client ID/secret, and make sure each person's SAIP account email matches their Google email. Keep a local `super_admin` password account as break-glass.
6. **Integrations (SIEM / webhooks)**: add destinations, use *Test*, check the delivery log. Webhooks are HMAC-signed (`X-SAIP-Signature`); store the secret at the receiver.
7. **Settings, Retention**: set `retention_events_days`, `retention_discovery_days`, `retention_heartbeat_days` (0 = keep forever; heartbeats default to 90).
8. **Collectors & Monitoring**: create the enrollment key (shown once) and use **Download collector package** for deployment.

---

## 6. Deploying collectors to workstations

The full step-by-step is in the in-app **Getting Started, Install the collector on workstations**. Summary:

1. Console, **Collectors & Monitoring, Download collector package** (`SaipCollector.zip`; it contains the server address, never the key).
2. On each workstation: extract, open PowerShell **as Administrator** in the folder, then
   ```
   Set-ExecutionPolicy -Scope Process Bypass -Force
   .\Install-Collector.ps1 -ServerUrl https://your-host/api/v1 -EnrollmentKey <key>
   ```
   (`-AllowInsecureHttp` is for labs only, never production.)
3. The installer copies itself to `C:\Tools\SaipCollector`, installs/repairs Sysmon (and proves it logs DNS), sets Chrome/Edge/Brave/Firefox machine policies so browser lookups become visible, enrolls the PC and schedules the collector every 5 minutes as SYSTEM. It ends with an OK/ATTENTION summary.
4. Console, **Collectors & Monitoring**: **Authorize** the PC (Pending to Authorized).
5. Verify on the PC: `C:\Tools\SaipCollector\Show-SysmonDns.ps1 -Match 'chrome|msedge'`. In SAIP the workstation appears under **Workstations** within a few minutes.
6. Mass rollout: GPO startup script, Intune or SCCM running the same command as SYSTEM. Use a pilot group first.

Notes for IT:
- Browser policy changes take effect when the browser next starts (`-RestartBrowsers` forces it; unsaved browser work is lost).
- The policies disable the browser's built-in DNS / DNS-over-HTTPS on managed PCs. Tell your security and network teams. `Uninstall-Collector.ps1` restores the previous values.
- ChatGPT and Gemini share CDN IP ranges with other sites, so they are detected by DNS only. The optional network-connection mode (`-EnableNetwork`) helps only for services on dedicated IPs.
- The enrollment key only registers a PC; each PC then gets its own private key. If a PC is lost or retired, delete/revoke it in the console.
- Update by running `Install-Collector.ps1` from a newer package (the existing config is kept). Remove with `Uninstall-Collector.ps1 [-RemoveSysmon] [-RemoveData]`.

---

## 7. Scheduled jobs (Windows Task Scheduler; use cron on Linux)

| Job | Command | Frequency |
|-----|---------|-----------|
| Retention purge | `php C:\path\saip\tools\purge.php` | Daily 02:00 |
| SIEM/webhook dispatcher (retries) | `php C:\path\saip\tools\dispatch-integrations.php` | Every 1-5 minutes |
| IP ownership map | `php C:\path\saip\tools\refresh-ip-map.php` | Weekly |
| Database backup | `mysqldump --single-transaction -u backup -p saip > saip-YYYYMMDD.sql` | Daily, copy offsite, test restores |

Run `php tools\purge.php --dry-run` first to see what retention would delete.

---

## 8. Backup, restore and upgrade

**Back up:** (1) the database, (2) `config/config.php`, (3) `config/app.key`, stored apart from the database dump (the dump alone cannot decrypt secrets). The audit log lives in the database, so it is covered.

**Restore:** install the code, restore `config.php`, `installed.lock` and the **same** `app.key`, import the dump, then open the site (if it redirects to the upgrade page, run it).

**Upgrade to a newer release (web):**
1. Back up the database and the `config/` folder.
2. Extract the new package over the existing folder **without deleting `config/`** (the package contains no `config.php`/`app.key`, so they are kept).
3. Browse to the site. Because the files are newer than the database, you are sent to `install.php` (collectors receive a temporary 503 and retry; nothing is lost).
4. The upgrade page lists the installed version, the new version and the pending database migrations. Sign in as a **platform administrator (super_admin)**, tick the backup box, optionally enter an administrative database login (needed when new tables are created, it also refreshes least-privilege grants; never stored), and click **Upgrade now**.
5. Smoke-test: sign in, open Dashboard, Inventory and Collectors; confirm a collector heartbeat arrives.

**Upgrade from an older install that predates the installer:** copy the new files over it, add `config/installed.lock` with `{"version":"0.0.0"}`, and open the site: the upgrade page applies every migration it is missing. Or run the wizard against the old database and choose *Use existing data*.

**Upgrade (CLI):** `php tools/migrate.php` (admin DB account), `php tools/db-grants.php saip_app`, then set the `version` in `config/installed.lock` to the new `VERSION`.

Rollback: restore the backup; `php tools/migrate.php down` reverts the latest migration if needed. Releases add numbered migrations in `sql/migrations`; they are applied in order and recorded, so any older version upgrades straight to the newest.

## 9. Day-to-day operations

- **Dashboard / Reports:** sanctioned vs unsanctioned trend, department adoption, coverage; CSV/XLSX exports.
- **Inventory:** shows only services that were *detected* or added manually/sanctioned; the full registry is under **AI Services & DNS Registry**.
- **Discovery:** unknown AI-looking domains seen on workstations; classify them into a service, mark under review, or exclude.
- **Collectors & Monitoring:** watch for *offline* collectors (no heartbeat for 15 minutes) and *pending* approvals.
- **Audit log:** every administrative action with user, IP and request id; export for compliance. The application account cannot edit or delete it.
- **Deleting data:** console deletions show an impact preview first. Deleting a service removes its domains and events; deleting a workstation removes its history.
- **Clean test data:** `php tools\cleandemo.php <slug>` previews; add `--yes` to delete all events, workstations and discovery data (AI services and the registry are kept); `--demo-only` limits it to `DEMO-*` machines.

---

## 10. Security reference

CSRF token + Origin check on every state-changing console call; `SameSite=Strict`, `HttpOnly`, `__Host-` + `Secure` session cookies on HTTPS; Argon2id passwords with lockout and rate limits; strict Content-Security-Policy and security headers; parameterised SQL only; tenant scoping on every query; secrets encrypted with libsodium (`config/app.key`); SSRF guard on outbound integrations; CSV formula-injection neutralised in exports; append-only audit trail.

Review periodically: role assignments (quarterly), Google-linked accounts, integration destinations, who holds enrollment keys.

---

## 11. Troubleshooting

| Symptom | Check |
|---------|-------|
| Blank page / 500 | PHP error log; DB credentials in `config/config.php`; `php tools\migrate.php status`. |
| 404 on every page | `mod_rewrite` enabled, `AllowOverride All`, correct sub-path. |
| Cannot log in after moving to HTTPS | Clear cookies (the name changes to `__Host-saip_sid`); confirm the app sees HTTPS (proxy scheme and `trusted_proxies`). |
| Locked out | Wait for the lockout to expire, or create a new break-glass admin: `php tools\create-admin.php <newname> "<password>" super_admin`. |
| Google "state mismatch" / redirect error | Redirect URI in Google Cloud must match exactly (HTTPS); server clock correct; the user's email exists in SAIP. |
| Collector installs but nothing appears | PC still **Pending**: authorize it. Wrong `serverUrl` (placeholder or `localhost`); firewall; run `Show-SysmonDns.ps1`; read `C:\ProgramData\SaipCollector\collector-error.log`. |
| Sysmon error 32 / file in use | Restart Windows and run `Install-Collector.ps1` again (it self-repairs). |
| Browser lookups missing | Browser not restarted since install, or another management tool overrides the policy (`edge://policy`, `chrome://policy`). |
| Webhook/SIEM not delivering | Integrations delivery log; dispatcher job running; destination allowed (`allow_private` / `allow_http`); secret/token correct. |
| Secrets cannot be decrypted | `config/app.key` differs from the key used when they were saved: restore the original key or re-enter the secrets. |
| Database growing fast | Set retention days and schedule `purge.php`. |

---

## 12. Limits to communicate to the business

Counts are *observed DNS lookups*, not sessions or minutes; no page content, prompts or user names are read. Windows endpoints only. Services on shared CDNs are detected through DNS only. Unmanaged devices and PCs without the collector are invisible. SAIP shows usage; it does not block it.

---

## 13. Pre-launch sign-off checklist

- [ ] HTTPS valid, HTTP redirects, HSTS set
- [ ] Installed with the web wizard (`config/installed.lock` present); `env=production`, `auto_authorize=false`
- [ ] `install.php` restricted or deleted; wizard was not exposed to the internet while open
- [ ] `saip_app` DB account in use, `db-grants.php` run, `root` not used
- [ ] `initial-admin.txt` deleted, admin password changed, named accounts created
- [ ] `app.key` and `config.php` backed up offline
- [ ] Lock-down URLs (section 3) return 404/403
- [ ] Legacy folders, tests and demo data removed
- [ ] Scheduled jobs and DB backups created; one restore tested
- [ ] Pilot collector installed, authorized and visible in Workstations
- [ ] Google sign-in tested (if used) and a local break-glass admin retained
- [ ] SIEM/webhook test delivery succeeded (if used)
- [ ] Retention configured and approved by the data owner
