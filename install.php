<?php
declare(strict_types=1);

/**
 * SAIP web installer and upgrader.
 *   Not installed yet  -> setup wizard (requirements, site URL, database, data choice, company and administrator).
 *   Already installed  -> upgrade page (applies new database migrations after a super administrator signs in).
 * Once installed the wizard is locked (config/installed.lock). Delete this file after installation if the wizard could not.
 */

define('SAIP_INSTALLER', true);
require __DIR__ . '/app/Installer.php';

use Saip\Installer as I;

$cspNonce = base64_encode(random_bytes(12));
header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-$cspNonce'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-store');

$https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
session_name('saip_install');
session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'httponly' => true, 'samesite' => 'Strict', 'secure' => $https]);
session_start();
$_SESSION['csrf'] ??= bin2hex(random_bytes(24));
$csrf = $_SESSION['csrf'];

function e(mixed $v): string { return htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function post(string $k, string $d = ''): string { $v = $_POST[$k] ?? $d; return is_string($v) ? trim($v) : $d; }

function sameOrigin(): bool
{
    $o = $_SERVER['HTTP_ORIGIN'] ?? ($_SERVER['HTTP_REFERER'] ?? '');
    if ($o === '') return true;
    return (parse_url($o, PHP_URL_HOST) ?? '') === (parse_url('//' . ($_SERVER['HTTP_HOST'] ?? ''), PHP_URL_HOST) ?? '-');
}

function jsonOut(array $d, int $status = 200): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($d);
    exit;
}

/** Runs one of the CLI tools in its own scope with the given arguments and returns what it printed. */
function runTool(string $file, array $args): string
{
    $argv = array_merge(['tool'], $args);
    ob_start();
    try { require __DIR__ . '/tools/' . $file; } finally { $out = (string)ob_get_clean(); }
    return trim($out);
}

function layout(string $title, string $body): void
{
    global $cspNonce;
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">'
        . '<title>' . e($title) . '</title><style>
:root{--bg:#0f1226;--card:#171a36;--line:#2a2f5a;--tx:#e8eaf6;--mut:#9aa1c9;--ac:#5b8cff;--ok:#2fbf71;--bad:#ff5d6c;--warn:#f5b042}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:15px/1.5 system-ui,Segoe UI,Roboto,sans-serif}
.wrap{max-width:860px;margin:0 auto;padding:28px 16px 60px}h1{font-size:1.5rem;margin:0 0 4px}h2{font-size:1.05rem;margin:0 0 12px}
.sub{color:var(--mut);margin:0 0 22px}.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin-bottom:16px}
label{display:block;font-size:.85rem;color:var(--mut);margin:12px 0 4px}input[type=text],input[type=password],input[type=number],input[type=email],select{width:100%;padding:9px 11px;border-radius:8px;border:1px solid var(--line);background:#0c0f24;color:var(--tx);font:inherit}
input:focus,select:focus{outline:2px solid var(--ac);outline-offset:1px}.row{display:grid;grid-template-columns:1fr 1fr;gap:0 14px}@media(max-width:640px){.row{grid-template-columns:1fr}}
.opt{display:flex;gap:10px;align-items:flex-start;padding:10px 12px;border:1px solid var(--line);border-radius:10px;margin:8px 0;cursor:pointer}.opt input{margin-top:4px}
.opt b{display:block}.opt span{color:var(--mut);font-size:.85rem}.hint{color:var(--mut);font-size:.8rem;margin-top:4px}
button,.btn{background:var(--ac);color:#fff;border:0;border-radius:8px;padding:10px 18px;font:inherit;font-weight:600;cursor:pointer;text-decoration:none;display:inline-block}
button.alt{background:transparent;border:1px solid var(--line);color:var(--tx)}button:disabled{opacity:.5;cursor:not-allowed}
table{width:100%;border-collapse:collapse}td{padding:6px 8px;border-top:1px solid var(--line);vertical-align:top}td:first-child{width:46%}
.ok{color:var(--ok);font-weight:700}.bad{color:var(--bad);font-weight:700}.warn{color:var(--warn);font-weight:700}
.msg{padding:10px 12px;border-radius:8px;margin:10px 0;border:1px solid var(--line)}.msg.bad{border-color:var(--bad);background:#3a1620}.msg.ok{border-color:var(--ok);background:#12301f}.msg.warn{border-color:var(--warn);background:#33290f}
code,pre{background:#0c0f24;border-radius:6px;padding:2px 6px;font:13px Consolas,monospace}pre{padding:12px;overflow:auto;white-space:pre-wrap}
.key{font:16px Consolas,monospace;word-break:break-all;background:#0c0f24;border:1px dashed var(--ac);padding:12px;border-radius:8px}.hide{display:none}
ul.log{list-style:none;margin:0;padding:0}ul.log li{padding:4px 0;border-top:1px solid var(--line)}ul.log li:first-child{border:0}
</style></head><body><div class="wrap">' . $body . '</div></body></html>';
}

// ---------------------------------------------------------------------------------------------------------------------------------
// UPGRADE MODE (already installed)
// ---------------------------------------------------------------------------------------------------------------------------------
if (I::installed()) {
    $lock = I::lock();
    $cfg = is_file(__DIR__ . '/config/config.php') ? (require __DIR__ . '/config/config.php') : [];
    $codeVersion = I::version();
    $msg = '';
    $log = [];
    $pending = [];
    $runtime = null;
    try {
        $db = $cfg['db'] ?? [];
        $runtime = I::connect((string)($db['host'] ?? '127.0.0.1'), (int)($db['port'] ?? 3306), (string)($db['user'] ?? ''), (string)($db['password'] ?? ''), (string)($db['name'] ?? ''), $db['ssl_ca'] ?? null);
        $pending = I::inspect($runtime)['pending'];
    } catch (Throwable $ex) {
        $msg = 'Cannot connect to the database with the saved settings: ' . I::explain($ex);
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && $runtime) {
        try {
            if (!hash_equals($csrf, post('csrf')) || !sameOrigin()) throw new RuntimeException('Session expired. Reload the page and try again.');
            $_SESSION['tries'] = ($_SESSION['tries'] ?? 0) + 1;
            if ($_SESSION['tries'] > 8) throw new RuntimeException('Too many attempts. Close the browser and try again later.');
            usleep(400000);
            $u = $runtime->prepare("SELECT password_hash FROM admin_users WHERE username = ? AND role = 'super_admin' AND tenant_id IS NULL AND active = 1");
            $u->execute([post('su')]);
            $hash = $u->fetchColumn();
            if (!$hash || !password_verify((string)($_POST['sp'] ?? ''), (string)$hash)) throw new RuntimeException('Sign-in failed: platform administrator username or password is wrong.');
            if (post('backup') !== '1') throw new RuntimeException('Confirm that you have a current database backup.');

            $admin = $runtime;
            if (post('au') !== '') {
                $admin = I::connect((string)$db['host'], (int)$db['port'], post('au'), (string)($_POST['ap'] ?? ''), (string)$db['name'], $db['ssl_ca'] ?? null);
                $log[] = 'Connected with the administrative database account (used only for this upgrade; not stored).';
            }
            $applied = I::migrate($admin);
            foreach ($applied as $n) $log[] = "Applied database migration $n";
            if (!$applied) $log[] = 'No database changes were needed.';
            if (post('au') !== '' && !empty($lock['app_user'])) {
                $n = I::grantLeastPrivilege($admin, (string)$db['name'], (string)$lock['app_user'], $lock['grant_hosts'] ?? ['localhost']);
                $log[] = "Re-applied least-privilege grants on $n tables for {$lock['app_user']}.";
            } elseif ($applied) {
                $log[] = 'Note: new tables were created by the application account only if it has CREATE rights. If pages fail with permission errors, re-run this upgrade with the administrative database account so grants are refreshed.';
            }
            $lock['previous_version'] = $lock['version'] ?? null;
            $lock['version'] = $codeVersion;
            $lock['upgraded_at'] = gmdate('c');
            I::writeLock($lock);
            require_once __DIR__ . '/app/bootstrap.php';
            try { Saip\Audit::log('installer', 'application_upgraded', $codeVersion, ['from' => $lock['previous_version'], 'migrations' => $applied], null); } catch (Throwable) { /* audit is best effort here */ }
            $_SESSION['tries'] = 0;
            $pending = [];
            $msg = '';
            $done = true;
        } catch (Throwable $ex) {
            $msg = $ex instanceof RuntimeException ? $ex->getMessage() : 'Upgrade failed: ' . I::explain($ex);
        }
    }

    $body = '<h1>SAIP upgrade</h1><p class="sub">This application is already installed. This page applies database changes that come with a newer version.</p>';
    $base = I::siteUrl();
    if (!empty($done)) {
        $body .= '<div class="card"><div class="msg ok">Upgrade complete. Now running version <b>' . e($codeVersion) . '</b>.</div><ul class="log">';
        foreach ($log as $l) $body .= '<li>' . e($l) . '</li>';
        $body .= '</ul><p><a class="btn" href="' . e($base) . '/login">Open SAIP</a></p></div>';
        layout('SAIP upgrade', $body);
        exit;
    }
    $needs = $pending || ($lock['version'] ?? '') !== $codeVersion;
    $body .= '<div class="card"><table><tr><td>Installed version</td><td>' . e($lock['version'] ?? 'unknown') . '</td></tr><tr><td>Version of the files on this server</td><td>' . e($codeVersion) . '</td></tr>'
        . '<tr><td>Pending database migrations</td><td>' . ($pending ? e(implode(', ', $pending)) : 'none') . '</td></tr></table></div>';
    if ($msg) $body .= '<div class="msg bad">' . e($msg) . '</div>';
    if (!$needs) {
        $body .= '<div class="msg ok">Everything is up to date. Nothing to do.</div><p><a class="btn" href="' . e($base) . '/login">Open SAIP</a></p>';
    } elseif ($runtime) {
        $body .= '<form method="post" class="card" autocomplete="off"><h2>Run the upgrade</h2>
<div class="msg warn">Take a database backup first (for example <code>mysqldump --single-transaction saip &gt; backup.sql</code>) and keep the existing <code>config/</code> folder.</div>
<input type="hidden" name="csrf" value="' . e($csrf) . '">
<div class="row"><div><label>Platform administrator (super_admin) username</label><input type="text" name="su" required></div><div><label>Password</label><input type="password" name="sp" required></div></div>
<div class="row"><div><label>Administrative database user (optional)</label><input type="text" name="au" placeholder="needed when the app account cannot create tables"></div><div><label>Administrative database password</label><input type="password" name="ap"></div></div>
<p class="hint">The administrative database login is used only for this upgrade and is never saved. It also refreshes the least-privilege grants for new tables.</p>
<label class="opt"><input type="checkbox" name="backup" value="1"><span><b>I have a current backup</b>of the database and the config folder.</span></label>
<p><button type="submit">Upgrade now</button></p></form>';
    }
    layout('SAIP upgrade', $body);
    exit;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// INSTALL MODE
// ---------------------------------------------------------------------------------------------------------------------------------
$reqOk = I::requirementsMet();

function sanitizeDbPost(): array
{
    return [
        'host' => post('db_host', '127.0.0.1'), 'port' => (int)post('db_port', '3306'), 'name' => post('db_name', 'saip'),
        'mode' => post('db_mode', 'create'), 'adm_user' => post('adm_user'), 'adm_pass' => (string)($_POST['adm_pass'] ?? ''),
        'app_user' => post('app_user'), 'app_pass' => (string)($_POST['app_pass'] ?? ''), 'allowed' => post('allowed_from', 'localhost'), 'ca' => post('db_ca'),
    ];
}

function validateDb(array $d): ?string
{
    if (!I::validHost($d['host'])) return 'Database host is not valid.';
    if ($d['port'] < 1 || $d['port'] > 65535) return 'Database port is not valid.';
    if (!I::validName($d['name'])) return 'Database name may contain only letters, digits and underscore (max 64).';
    if ($d['mode'] === 'create') {
        if ($d['adm_user'] === '') return 'Enter an administrative database account that may create databases and users.';
        if (!I::validName($d['app_user'])) return 'Application database user may contain only letters, digits and underscore.';
        if (!I::validHost($d['allowed'])) return '"Allowed from" is not valid.';
    } elseif ($d['app_user'] === '') return 'Enter the database user and password.';
    if ($d['ca'] !== '' && !is_file($d['ca'])) return 'The TLS CA file was not found on this server.';
    return null;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && post('action') === 'test') {
    if (!hash_equals($csrf, post('csrf')) || !sameOrigin()) jsonOut(['ok' => false, 'message' => 'Session expired. Reload the page.'], 403);
    $d = sanitizeDbPost();
    if ($err = validateDb($d)) jsonOut(['ok' => false, 'message' => $err]);
    try {
        $user = $d['mode'] === 'create' ? $d['adm_user'] : $d['app_user'];
        $pass = $d['mode'] === 'create' ? $d['adm_pass'] : $d['app_pass'];
        $srv = I::connect($d['host'], $d['port'], $user, $pass, null, $d['ca'] ?: null);
        $ver = (string)$srv->query('SELECT VERSION()')->fetchColumn();
        $exists = (bool)$srv->query('SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = ' . $srv->quote($d['name']))->fetchColumn();
        $res = ['ok' => true, 'message' => "Connected to database server $ver.", 'exists' => $exists, 'inspect' => null];
        if ($exists) {
            $w = I::connect($d['host'], $d['port'], $user, $pass, $d['name'], $d['ca'] ?: null);
            $res['inspect'] = I::inspect($w);
        } elseif ($d['mode'] === 'existing') { $res = ['ok' => false, 'message' => 'Connected, but that database does not exist. Create it first or choose "Create it for me".']; }
        jsonOut($res);
    } catch (Throwable $ex) {
        jsonOut(['ok' => false, 'message' => I::explain($ex)]);
    }
}

$result = null;
$error = '';
$v = fn (string $k, string $d = ''): string => $_SERVER['REQUEST_METHOD'] === 'POST' ? post($k, $d) : $d;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && post('action') === 'install') {
    $log = [];
    try {
        if (!hash_equals($csrf, post('csrf')) || !sameOrigin()) throw new RuntimeException('Session expired. Reload the page and try again.');
        if (!$reqOk) throw new RuntimeException('Fix the failed requirements first.');
        @set_time_limit(600);
        $say = function (string $m) use (&$log): void { $log[] = $m; };

        // 1. validate -----------------------------------------------------------------------------------------------------------
        $d = sanitizeDbPost();
        if ($err = validateDb($d)) throw new RuntimeException($err);
        $site = rtrim(post('site_url'), '/');
        $p = parse_url($site);
        if (!$p || !in_array($p['scheme'] ?? '', ['http', 'https'], true) || empty($p['host'])) throw new RuntimeException('Site address must start with http:// or https://.');
        $env = post('env') === 'development' ? 'development' : 'production';
        $dataMode = in_array(post('data_mode'), ['fresh', 'demo', 'migrate'], true) ? post('data_mode') : 'fresh';
        $proxies = array_values(array_filter(array_map('trim', explode(',', post('proxies'))), static fn ($x) => $x !== ''));
        foreach ($proxies as $px) if (!filter_var($px, FILTER_VALIDATE_IP)) throw new RuntimeException("Trusted proxy \"$px\" is not an IP address.");

        $company = post('company');
        $slug = trim((string)preg_replace('/[^a-z0-9]+/', '-', strtolower(post('slug') !== '' ? post('slug') : $company)), '-');
        $aUser = post('a_user');
        $aPass = (string)($_POST['a_pass'] ?? '');
        $needAdmin = $dataMode !== 'migrate' || $aUser !== '';
        if ($dataMode !== 'migrate' && ($company === '' || mb_strlen($company) > 150 || $slug === '')) throw new RuntimeException('Enter the company name.');
        if ($needAdmin) {
            if (!preg_match('/^[A-Za-z0-9._@-]{3,60}$/', $aUser)) throw new RuntimeException('Administrator username must be 3-60 characters (letters, digits . _ @ -).');
            if (post('a_email') !== '' && !filter_var(post('a_email'), FILTER_VALIDATE_EMAIL)) throw new RuntimeException('Administrator email is not valid.');
            if ($aPass !== (string)($_POST['a_pass2'] ?? '')) throw new RuntimeException('The two administrator passwords do not match.');
            if (strlen($aPass) < 12) throw new RuntimeException('Administrator password must be at least 12 characters.');
            if (stripos($aPass, $aUser) !== false) throw new RuntimeException('Administrator password must not contain the username.');
            if (count(array_filter([preg_match('/[a-z]/', $aPass), preg_match('/[A-Z]/', $aPass), preg_match('/\d/', $aPass), preg_match('/[^A-Za-z0-9]/', $aPass)])) < 3) throw new RuntimeException('Use at least three of: lowercase, uppercase, digits, symbols in the administrator password.');
        }
        $say('Settings validated');

        // 2. database server, database and account ------------------------------------------------------------------------------
        $appUser = $d['mode'] === 'create' ? $d['app_user'] : $d['app_user'];
        $appPass = $d['mode'] === 'create' ? ($d['app_pass'] !== '' ? $d['app_pass'] : I::randomPassword()) : $d['app_pass'];
        $hosts = I::accountHosts($d['allowed']);
        $ca = $d['ca'] ?: null;
        if ($d['mode'] === 'create') {
            $srv = I::connect($d['host'], $d['port'], $d['adm_user'], $d['adm_pass'], null, $ca);
            $say('Connected to the database server with the administrative account');
            I::createDatabaseAndUser($srv, $d['name'], $appUser, $appPass, $hosts);
            $say("Database {$d['name']} ready; application account $appUser created for " . implode(', ', $hosts));
            $work = I::connect($d['host'], $d['port'], $d['adm_user'], $d['adm_pass'], $d['name'], $ca);
        } else {
            $work = I::connect($d['host'], $d['port'], $appUser, $appPass, $d['name'], $ca);
            $say('Connected to the existing database');
        }

        // 3. existing data ------------------------------------------------------------------------------------------------------
        $found = I::inspect($work);
        if ($dataMode === 'migrate') {
            if (!$found['saip']) throw new RuntimeException('There is no earlier SAIP data in this database to migrate. Choose "Fresh install" instead.');
            $say("Existing SAIP data kept: {$found['companies']} company(ies), {$found['users']} user(s), {$found['events']} event(s)");
        } elseif ($found['tables'] > 0) {
            if (post('wipe') !== $d['name']) throw new RuntimeException('The database already contains tables. To erase them type the database name in the confirmation box, or choose "Use existing data".');
            $say('Erased ' . I::dropAll($work) . ' existing tables');
        }

        // 4. schema, catalogue, migrations --------------------------------------------------------------------------------------
        I::runSql($work, __DIR__ . '/sql/schema.sql');
        $say('Database structure ready');
        if ((int)$work->query('SELECT COUNT(*) FROM catalog_services')->fetchColumn() === 0) { I::runSql($work, __DIR__ . '/sql/catalog_seed.sql'); $say('Template AI catalogue loaded'); }
        $applied = I::migrate($work);
        $say($applied ? count($applied) . ' migration(s) applied (' . implode(', ', $applied) . ')' : 'Database already at the latest version');
        if ($d['mode'] === 'create') $say('Least-privilege grants applied to ' . I::grantLeastPrivilege($work, $d['name'], $appUser, $hosts) . ' tables (audit log is append-only)');
        else $say('Note: an existing account was used as-is. For production create a dedicated account and run tools/db-grants.php.');

        // 5. configuration files ------------------------------------------------------------------------------------------------
        $conf = require __DIR__ . '/config/config.example.php';
        $conf['env'] = $env;
        $conf['base_url'] = $site;
        $conf['db'] = ['host' => $d['host'], 'port' => $d['port'], 'name' => $d['name'], 'user' => $appUser, 'password' => $appPass, 'ssl_ca' => $ca];
        $conf['auto_authorize'] = false;
        $conf['trusted_proxies'] = $proxies;
        unset($conf['admin_api_key'], $conf['viewer_allowed_ips']);
        $conf['enrollment_key'] = bin2hex(random_bytes(16));
        I::writeConfig($conf);
        $say('config/config.php written');
        $keyWasMissing = !is_file(__DIR__ . '/config/app.key');
        if ($dataMode !== 'migrate' || $keyWasMissing) { I::newAppKey(); $say('Encryption key created (config/app.key) - back it up separately'); }
        elseif ($dataMode === 'migrate') $say('Existing encryption key kept');
        if ($dataMode === 'migrate' && !empty($keyWasMissing)) $say('WARNING: no earlier config/app.key was found, so secrets saved by the old install (Google client secret, webhook/SIEM tokens) cannot be decrypted. Copy the old app.key into config/ or re-enter them.');

        // 6. application data ---------------------------------------------------------------------------------------------------
        require_once __DIR__ . '/app/bootstrap.php';
        Saip\Db::val('SELECT COUNT(*) FROM tenants');
        $say('Application account can read the database');
        $enrollment = null;
        $tenantSlug = null;
        if ($dataMode !== 'migrate') {
            $t = Saip\Tenants::create($company, $slug);
            $enrollment = $t['enrollment_key']; $tenantSlug = $t['slug'];
            $say("Company \"$company\" created with the AI catalogue, ISO 42001 controls and default policies");
        }
        if ($needAdmin) {
            if (Saip\Db::val('SELECT 1 FROM admin_users WHERE username = ?', [$aUser])) throw new RuntimeException("A user named \"$aUser\" already exists in this database. Choose another administrator name.");
            Saip\Db::run('INSERT INTO admin_users (tenant_id, username, display_name, email, password_hash, role, password_changed_at) VALUES (NULL,?,?,?,?,?,UTC_TIMESTAMP())',
                [$aUser, $aUser, post('a_email') ?: null, Saip\Security\Auth::hashPassword($aPass), 'super_admin']);
            $say("Platform administrator \"$aUser\" created");
        }
        if ($dataMode !== 'migrate') {
            if (post('registry') === '1') {
                $o = runTool('load-top100.php', [$tenantSlug]); $say('Top-100 AI services registry loaded');
                $o2 = runTool('load-known-ai.php', [$tenantSlug]); $say('Well-known AI services loaded');
            }
            if ($dataMode === 'demo') { runTool('loaddemodata.php', [$tenantSlug]); $say('Demo data loaded (DEMO-* workstations, 30 days of events). Remove later with tools/cleandemo.php'); }
        }
        try { Saip\Audit::log('installer', 'application_installed', I::version(), ['data_mode' => $dataMode, 'database' => $d['name'], 'migrations' => count($applied)], null); } catch (Throwable) { }

        // 7. lock ---------------------------------------------------------------------------------------------------------------
        I::writeLock(['version' => I::version(), 'installed_at' => gmdate('c'), 'data_mode' => $dataMode, 'db_name' => $d['name'], 'app_user' => $d['mode'] === 'create' ? $appUser : null, 'grant_hosts' => $hosts, 'base_url' => $site]);
        $say('Installation locked');
        $deleted = false;
        if (post('delete_self') === '1') $deleted = @unlink(__FILE__);
        $say($deleted ? 'install.php removed from the server' : 'install.php is now inactive (it only offers upgrades). Delete it when you no longer need upgrades.');
        $result = ['log' => $log, 'enrollment' => $enrollment, 'site' => $site, 'slug' => $tenantSlug, 'env' => $env, 'mode' => $dataMode, 'deleted' => $deleted];
    } catch (Throwable $ex) {
        $error = ($ex instanceof RuntimeException || $ex instanceof PDOException ? '' : 'Unexpected error: ') . ($ex instanceof PDOException ? I::explain($ex) : $ex->getMessage());
        $log[] = 'STOPPED: ' . $error;
        $failedLog = $log;
    }
}

// ----- result page -----
if ($result) {
    $b = '<h1>Installation complete</h1><p class="sub">SAIP ' . e(I::version()) . ' is ready.</p><div class="card"><h2>What was done</h2><ul class="log">';
    foreach ($result['log'] as $l) $b .= '<li><span class="ok">&#10003;</span> ' . e($l) . '</li>';
    $b .= '</ul></div>';
    if ($result['enrollment']) {
        $b .= '<div class="card"><h2>Collector enrollment key (shown once)</h2><div class="key" id="ek">' . e($result['enrollment']) . '</div>
<p class="hint">Copy it now. Workstations use it to register; only its hash is stored. You can create a new one anytime under Collectors &amp; Monitoring.</p></div>';
    }
    $b .= '<div class="card"><h2>Next steps</h2><ol>
<li><a class="btn" href="' . e($result['site']) . '/login">Open SAIP and sign in</a></li>
<li>Collectors &amp; Monitoring &rarr; <b>Download collector package</b> and install it on a pilot workstation (Getting Started explains each step).</li>';
    if (str_starts_with($result['site'], 'http://') && $result['env'] === 'production') $b .= '<li><span class="warn">Your address is plain http.</span> Put a TLS certificate on this site before real use; collectors send keys and data.</li>';
    $b .= '<li>Back up <code>config/app.key</code> and <code>config/config.php</code> somewhere safe, separately from database backups.</li>
<li>Schedule the nightly purge, integration dispatcher and database backup (see <code>AdminGuide-README.md</code>).</li>';
    if (!$result['deleted']) $b .= '<li>Optionally delete <code>install.php</code>; keep it if you want the web upgrade page for future versions.</li>';
    $b .= '</ol></div>';
    layout('SAIP installed', $b);
    exit;
}

// ----- wizard form -----
$site = $v('site_url', I::siteUrl());
$req = I::requirements();
$b = '<h1>SAIP setup</h1><p class="sub">Shadow AI Platform ' . e(I::version()) . ' &middot; this wizard installs the database, configuration and first administrator.</p>';
if ($error) {
    $b .= '<div class="msg bad"><b>Installation stopped.</b> ' . e($error) . '</div>';
    if (!empty($failedLog)) { $b .= '<div class="card"><ul class="log">'; foreach ($failedLog as $l) $b .= '<li>' . e($l) . '</li>'; $b .= '</ul><p class="hint">You can correct the settings below and run it again; completed steps are safe to repeat.</p></div>'; }
}
$b .= '<div class="card"><h2>1. Requirements</h2><table>';
foreach ($req as $q) $b .= '<tr><td>' . e($q['label']) . '<div class="hint">' . e($q['detail']) . '</div></td><td class="' . ($q['ok'] ? 'ok' : ($q['required'] ? 'bad' : 'warn')) . '">' . ($q['ok'] ? 'OK' : ($q['required'] ? 'MISSING' : 'Check')) . '</td></tr>';
$b .= '</table>' . ($reqOk ? '' : '<div class="msg bad">Fix the items marked MISSING, then reload this page.</div>') . '</div>';

if ($reqOk) {
    $chk = static fn (string $name, string $val, string $def = '') => ((($_SERVER['REQUEST_METHOD'] === 'POST' ? post($name) : $def) === $val) ? ' checked' : '');
    $b .= '<form method="post" autocomplete="off" id="f"><input type="hidden" name="csrf" value="' . e($csrf) . '"><input type="hidden" name="action" value="install">
<div class="card"><h2>2. Site</h2><label>Address people will use to open SAIP</label><input type="text" name="site_url" value="' . e($site) . '" required>
<p class="hint">Include the folder if SAIP is not at the site root, for example <code>https://saip.example.com</code> or <code>https://server/saip</code>. Used for collector download links and Google sign-in.</p>
<div class="row"><div><label>Environment</label><select name="env"><option value="production"' . ($v('env', 'production') === 'production' ? ' selected' : '') . '>Production</option><option value="development"' . ($v('env') === 'development' ? ' selected' : '') . '>Development / test</option></select></div>
<div><label>Trusted proxy IPs (optional)</label><input type="text" name="proxies" value="' . e($v('proxies')) . '" placeholder="only if behind a load balancer, e.g. 10.0.0.5"></div></div></div>

<div class="card"><h2>3. Database</h2>
<label class="opt"><input type="radio" name="db_mode" value="create"' . $chk('db_mode', 'create', 'create') . '><span><b>Create the database and a restricted application account for me (recommended)</b>Needs a MySQL/MariaDB administrator login once; it is not stored. The app then runs with an account that cannot change the schema or edit the audit log.</span></label>
<label class="opt"><input type="radio" name="db_mode" value="existing"' . $chk('db_mode', 'existing') . '><span><b>Use a database and account I already created</b>The database must exist and the account needs full rights on it.</span></label>
<div class="row"><div><label>Database host</label><input type="text" name="db_host" value="' . e($v('db_host', '127.0.0.1')) . '"></div><div><label>Port</label><input type="number" name="db_port" value="' . e($v('db_port', '3306')) . '"></div></div>
<div class="row"><div><label>Database name</label><input type="text" name="db_name" value="' . e($v('db_name', 'saip')) . '"></div><div><label>TLS CA file (remote database, optional)</label><input type="text" name="db_ca" value="' . e($v('db_ca')) . '" placeholder="/etc/ssl/certs/db-ca.pem"></div></div>
<div id="m_create"><div class="row"><div><label>Administrator DB user (e.g. root)</label><input type="text" name="adm_user" value="' . e($v('adm_user', 'root')) . '"></div><div><label>Administrator DB password</label><input type="password" name="adm_pass"></div></div>
<div class="row"><div><label>New application DB user</label><input type="text" name="app_user" value="' . e($v('app_user', 'saip_app')) . '" data-c="1"></div><div><label>Its password (blank = generate)</label><input type="password" name="app_pass" data-c="1"></div></div>
<label>Application account may connect from</label><input type="text" name="allowed_from" value="' . e($v('allowed_from', 'localhost')) . '"><p class="hint">Use <code>localhost</code> when the database is on this server, otherwise this web server&rsquo;s address or <code>%</code>.</p></div>
<div id="m_existing" class="hide"><div class="row"><div><label>Database user</label><input type="text" name="app_user" value="' . e($v('app_user')) . '" disabled data-e="1"></div><div><label>Database password</label><input type="password" name="app_pass" disabled data-e="1"></div></div></div>
<p><button type="button" class="alt" id="test">Test connection</button> <span id="tr"></span></p><div id="found" class="hide"></div></div>

<div class="card"><h2>4. Data</h2>
<label class="opt"><input type="radio" name="data_mode" value="fresh"' . $chk('data_mode', 'fresh', 'fresh') . '><span><b>Fresh install</b>Empty system with the AI service catalogue, ISO 42001 controls and default policies. Nothing else.</span></label>
<label class="opt"><input type="radio" name="data_mode" value="demo"' . $chk('data_mode', 'demo') . '><span><b>Fresh install with demo data</b>Adds sample workstations, 30 days of events, discovered domains and requests so you can explore. Remove later with <code>tools/cleandemo.php</code>. Not for production.</span></label>
<label class="opt"><input type="radio" name="data_mode" value="migrate"' . $chk('data_mode', 'migrate') . '><span><b>Use existing data (upgrade / migrate)</b>The database already holds an earlier SAIP install. Nothing is deleted; the structure is brought up to this version. Back it up first.</span></label>
<div id="d_registry"><label class="opt"><input type="checkbox" name="registry" value="1"' . ($_SERVER['REQUEST_METHOD'] === 'POST' ? (post('registry') === '1' ? ' checked' : '') : ' checked') . '><span><b>Load the AI registry</b>Top-100 AI services with FQDN, registrar and purpose, plus about 54 other well-known AI services.</span></label></div>
<div id="d_wipe" class="hide"><div class="msg warn">This database already contains tables. A fresh install erases them. To confirm, type the database name: <input type="text" name="wipe" style="max-width:220px" placeholder="database name"></div></div></div>

<div class="card"><h2>5. Company and administrator</h2>
<div id="d_company"><div class="row"><div><label>Company name</label><input type="text" name="company" value="' . e($v('company')) . '"></div><div><label>Short name (letters, digits, dash)</label><input type="text" name="slug" value="' . e($v('slug')) . '" placeholder="auto from the name"></div></div></div>
<p class="hint hide" id="d_admin_opt">Optional when migrating: fill this in only to add another platform administrator.</p>
<div class="row"><div><label>Platform administrator username</label><input type="text" name="a_user" value="' . e($v('a_user', 'admin')) . '"></div><div><label>Email (for Google sign-in, optional)</label><input type="email" name="a_email" value="' . e($v('a_email')) . '"></div></div>
<div class="row"><div><label>Password (12+ characters)</label><input type="password" name="a_pass"></div><div><label>Repeat password</label><input type="password" name="a_pass2"></div></div></div>

<div class="card"><label class="opt"><input type="checkbox" name="delete_self" value="1"><span><b>Delete install.php when finished</b>You lose the web upgrade page; upgrades can still be run with <code>php tools/migrate.php</code>.</span></label>
<p><button type="submit" id="go">Install SAIP</button></p></div></form>
<script nonce="' . $cspNonce . '">
const $=s=>document.querySelector(s), all=s=>[...document.querySelectorAll(s)], f=$("#f");
function sync(){
  const create=f.db_mode.value==="create", mode=f.data_mode.value;
  $("#m_create").classList.toggle("hide",!create); $("#m_existing").classList.toggle("hide",create);
  all("[data-c]").forEach(i=>i.disabled=!create); all("[data-e]").forEach(i=>i.disabled=create);
  $("#d_registry").classList.toggle("hide",mode==="migrate"); $("#d_company").classList.toggle("hide",mode==="migrate"); $("#d_admin_opt").classList.toggle("hide",mode!=="migrate");
  $("#d_wipe").classList.toggle("hide",!(window.__found&&window.__found.tables>0&&mode!=="migrate"));
}
f.addEventListener("change",sync); sync();
$("#test").onclick=async()=>{
  const r=$("#tr"); r.textContent="Testing..."; r.className="hint";
  const fd=new FormData(f); fd.set("action","test");
  try{
    const j=await (await fetch(location.pathname,{method:"POST",body:fd})).json();
    r.textContent=j.message; r.className=j.ok?"ok":"bad"; window.__found=j.inspect||null; const box=$("#found");
    if(j.ok&&j.inspect&&j.inspect.tables>0){
      const i=j.inspect; box.classList.remove("hide");
      if(i.saip){ box.innerHTML="<div class=\"msg warn\"><b>Existing SAIP data found:</b> "+i.companies+" company(ies), "+i.users+" user(s), "+i.events+" event(s); "+i.pending.length+" database update(s) pending. Choose <b>Use existing data</b> in step 4 to keep it and upgrade.</div>"; if(f.data_mode.value==="fresh") f.data_mode.value="migrate"; }
      else box.innerHTML="<div class=\"msg warn\">This database contains "+i.tables+" table(s) that are not SAIP data. Choosing a fresh install will erase them.</div>";
    } else box.classList.add("hide");
    sync();
  }catch(e){r.textContent="Test failed: "+e; r.className="bad";}
};
f.addEventListener("submit",()=>{const b=$("#go"); b.disabled=true; b.textContent="Installing... please wait";});
</script>';
}
layout('SAIP setup', $b);
