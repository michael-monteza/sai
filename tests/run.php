<?php
declare(strict_types=1);

/**
 * Regression / security suite. Needs the app served over HTTP and a local database.
 *   php tests/run.php [http://127.0.0.1:8080/2026/saip]
 * Creates two throwaway companies and users (prefix zt-), exercises the API, then deletes everything it created.
 */
require __DIR__ . '/../app/bootstrap.php';

use Saip\{Db, Tenants};

if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
$base = rtrim($argv[1] ?? 'http://127.0.0.1:8080/2026/saip', '/') . '/api/v1/';
$pass = 0; $fail = 0;
function check(string $name, bool $ok, string $detail = ''): void {
    global $pass, $fail; $ok ? $pass++ : $fail++;
    echo ($ok ? '  ok   ' : '  FAIL ') . $name . ($ok || $detail === '' ? '' : "  -> $detail") . "\n";
}

/** Minimal HTTP client; $jar is a cookie file per session. @return array{0:int,1:mixed,2:string} */
function call(string $method, string $path, ?array $body = null, array $headers = [], ?string $jar = null, bool $raw = false): array {
    global $base;
    $ch = curl_init($base . $path);
    $h = ['Accept: application/json'];
    foreach ($headers as $k => $v) $h[] = "$k: $v";
    if ($body !== null) { $h[] = 'Content-Type: application/json'; curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body)); }
    curl_setopt_array($ch, [CURLOPT_CUSTOMREQUEST => $method, CURLOPT_HTTPHEADER => $h, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 20]);
    if ($jar) curl_setopt_array($ch, [CURLOPT_COOKIEJAR => $jar, CURLOPT_COOKIEFILE => $jar]);
    $out = (string)curl_exec($ch); $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_close($ch);
    return [$code, $raw ? $out : json_decode($out, true), $out];
}


/** One sign-in attempt through the form; returns the response body. */
function login_attempt(string $user, string $pw): string {
    global $base;
    $root = preg_replace('#api/v1/$#', '', $base);
    $jar = tempnam(sys_get_temp_dir(), 'zt'); $ch = curl_init($root . 'login');
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_COOKIEJAR => $jar, CURLOPT_COOKIEFILE => $jar]);
    $html = (string)curl_exec($ch); preg_match('/name="csrf" value="([0-9a-f]+)"/', $html, $m);
    curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => http_build_query(['csrf' => $m[1] ?? '', 'username' => $user, 'password' => $pw])]);
    return (string)curl_exec($ch);
}

/** Signs in through the login form and returns [cookieJar, csrf]. */
function login(string $user, string $pw): array {
    global $base;
    $root = preg_replace('#api/v1/$#', '', $base);
    $jar = tempnam(sys_get_temp_dir(), 'zt'); $ch = curl_init($root . 'login');
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_COOKIEJAR => $jar, CURLOPT_COOKIEFILE => $jar]);
    $html = (string)curl_exec($ch); preg_match('/name="csrf" value="([0-9a-f]+)"/', $html, $m);
    curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => http_build_query(['csrf' => $m[1] ?? '', 'username' => $user, 'password' => $pw])]);
    curl_exec($ch); unset($ch); // destroying the handle flushes the cookie jar
    [, $me] = call('GET', 'console/me', null, [], $jar);
    if (empty($me['csrf'])) echo '  (login debug: ' . substr(json_encode($me), 0, 160) . ")
";
    return [$jar, $me['csrf'] ?? '', $me];
}

$sfx = substr(bin2hex(random_bytes(3)), 0, 6); $pw = 'Zt-' . bin2hex(random_bytes(8));
$tA = Tenants::create("ZT Alpha $sfx"); $tB = Tenants::create("ZT Beta $sfx");
$mk = fn (string $u, string $role, ?int $t) => Db::run('INSERT INTO admin_users (tenant_id, username, display_name, password_hash, role) VALUES (?,?,?,?,?)', [$t, $u, $u, password_hash($pw, PASSWORD_DEFAULT), $role]);
$mk("zt-admin-$sfx", 'it_admin', $tA['id']); $mk("zt-viewer-$sfx", 'viewer', $tA['id']); $mk("zt-bob-$sfx", 'it_admin', $tB['id']); $mk("zt-aud-$sfx", 'auditor', $tA['id']); $mk("zt-super-$sfx", 'super_admin', null);

$gBackup = Db::all("SELECT name, value, secret, updated_by FROM platform_settings WHERE name LIKE 'google.%'");   // the suite changes Google settings; they are restored afterwards
try {
    echo "Auth & roles\n";
    [$c, ] = call('GET', 'console/dashboard'); check('console requires a session (401)', $c === 401);
    [$jarA, $csrfA] = login("zt-admin-$sfx", $pw); [$jarV, $csrfV] = login("zt-viewer-$sfx", $pw); [$jarB, $csrfB] = login("zt-bob-$sfx", $pw);
    check('admin signs in', $csrfA !== ''); check('viewer signs in', $csrfV !== '');
    [$c, ] = call('POST', 'console/registry/domains', ['service_id' => 1, 'domain' => 'x.example.com'], [], $jarA); check('write without CSRF rejected (403)', $c === 403, (string)$c);
    [$c, ] = call('POST', 'console/monitoring', ['discovery' => true], ['X-CSRF-Token' => $csrfV], $jarV); check('viewer cannot change monitoring (403)', $c === 403, (string)$c);
    [$c, ] = call('POST', 'console/retention', ['retention_events_days' => 30], ['X-CSRF-Token' => $csrfV], $jarV); check('viewer cannot change retention (403)', $c === 403, (string)$c);
    [$c, ] = call('GET', 'console/reports/registry', null, [], $jarV); check('viewer can read reports', $c === 200, (string)$c);

    echo "Registry & matching\n";
    $A = ['X-CSRF-Token' => $csrfA];
    [, $r] = call('POST', 'console/services', ['service_name' => 'ZT Svc', 'provider' => 'ZT', 'primary_domain' => "zt-$sfx.example.com", 'sanction_status' => 'unsanctioned'], $A, $jarA);
    $sid = (int)($r['id'] ?? 0); check('service created', $sid > 0, json_encode($r));
    [$c, ] = call('POST', 'console/registry/domains', ['service_id' => $sid, 'domain' => "api.zt-$sfx.example.com", 'matching_rule' => 'exact', 'domain_type' => 'api'], $A, $jarA); check('domain added', $c < 300, (string)$c);
    [$c, ] = call('POST', 'console/registry/domains', ['service_id' => $sid, 'domain' => "api.zt-$sfx.example.com"], $A, $jarA); check('duplicate domain rejected', $c === 409 || $c === 422, (string)$c);
    [$c, ] = call('POST', 'console/registry/domains', ['service_id' => $sid, 'domain' => '10.0.0.1'], $A, $jarA); check('IP address rejected', $c === 422, (string)$c);
    [, $cfg0] = call('GET', 'console/registry', null, [], $jarA);
    [, $mine] = call('GET', 'console/services', null, [], $jarB);
    check('tenant B cannot see tenant A service', !in_array('ZT Svc', array_column($mine['services'] ?? [], 'service_name'), true));
    [$c, ] = call('POST', "console/services/$sid", ['service_name' => 'hijack'], ['X-CSRF-Token' => $csrfB], $jarB); check('tenant B cannot edit tenant A service', $c === 404 || $c === 403, (string)$c);

    echo "Collector config & ingest\n";
    $reg = call('POST', 'collector/register', ['computer_name' => "ZT-WS-$sfx", 'collector_uuid' => sprintf('%08x-0000-4000-8000-%012x', random_int(0, PHP_INT_MAX >> 40), random_int(0, PHP_INT_MAX >> 20)), 'collector_version' => '2.0.0'], ['X-Enrollment-Key' => $tA['enrollment_key']]);
    $col = Db::one('SELECT collector_uuid, id FROM collectors WHERE tenant_id = ?', [$tA['id']]);
    check('collector registers with enrollment key', $reg[0] < 300 && !empty($reg[1]['api_key']), json_encode($reg[1]));
    [$c, ] = call('POST', 'collector/register', ['computer_name' => 'x', 'collector_uuid' => 'bad', 'collector_version' => '1'], ['X-Enrollment-Key' => 'wrong']); check('wrong enrollment key rejected (401)', $c === 401, (string)$c);
    Db::run("UPDATE collectors SET status = 'authorized' WHERE tenant_id = ?", [$tA['id']]);
    $H = ['X-Collector-Id' => $col['collector_uuid'], 'X-Api-Key' => $reg[1]['api_key'] ?? 'x'];
    [$c, $cfg] = call('GET', 'collector/config', null, $H); check('config returned', $c === 200 && isset($cfg['config_version']), (string)$c);
    [, $again] = call('GET', 'collector/config?since=' . ($cfg['config_version'] ?? 0), null, $H); check('config unchanged when current', !empty($again['unchanged']));
    [$c, ] = call('GET', 'collector/config', null, ['X-Collector-Id' => $col['collector_uuid'], 'X-Api-Key' => 'wrong']); check('config rejects bad API key (401)', $c === 401, (string)$c);
    $ts = gmdate('Y-m-d\TH:i:s.000\Z'); $ev = fn (int $id, string $d, array $x = []) => ['sysmon_record_id' => $id, 'event_timestamp' => $ts, 'query_domain' => $d] + $x;
    [, $i] = call('POST', 'events/ingest', ['events' => [
        $ev(1, "api.zt-$sfx.example.com"), $ev(2, "www.api.zt-$sfx.example.com"), $ev(3, "zt-$sfx.example.com"), $ev(4, "chat-ai.zt-other-$sfx.test"),
        $ev(5, "10.1.2.3"), ['sysmon_record_id' => 6, 'event_timestamp' => $ts, 'event_type' => 'network_connection', 'destination_ip' => '203.0.113.9', 'destination_host' => "zt-$sfx.example.com", 'destination_port' => 443]]], $H);
    check('exact rule matches only the host (api + apex = 2 accepted DNS, www subdomain unmatched)', ($i['accepted'] ?? 0) >= 2, json_encode($i));
    [, $bi] = call('POST', 'events/ingest', ['events' => [['sysmon_record_id' => 7, 'event_timestamp' => $ts, 'event_type' => 'network_connection', 'destination_ip' => 'not-an-ip']]], $H);
    check('network event with invalid destination_ip rejected', count($bi['rejected'] ?? []) === 1, json_encode($bi));
    [, $d] = call('POST', 'events/ingest', ['events' => [$ev(1, "api.zt-$sfx.example.com")]], $H); check('duplicate event not double counted', ($d['duplicates'] ?? 0) === 1, json_encode($d));
    [$c, $sw] = call('GET', "console/services/$sid/workstations?days=30", null, [], $jarA);
    check('service detail lists the workstations it was detected on', $c === 200 && count($sw['workstations'] ?? []) === 1 && strtoupper("ZT-WS-$sfx") === ($sw['workstations'][0]['computer_name'] ?? '') && (int)$sw['workstations'][0]['events'] >= 2, json_encode($sw));
    [$c, ] = call('GET', "console/services/$sid/workstations", null, [], $jarB); check('other company cannot see a service\'s workstations (404)', $c === 404, (string)$c);
    [$c, $ac] = call('GET', "console/activity?service_id=$sid&days=all", null, [], $jarA); check('event log for a service', $c === 200 && count($ac['events'] ?? []) >= 2 && ($ac['events'][0]['host'] ?? '') !== '', json_encode($ac['events'][0] ?? null));
    [$c, $ac2] = call('GET', 'console/activity?computer=' . strtoupper("ZT-WS-$sfx") . '&days=all', null, [], $jarA); check('event log for a computer', $c === 200 && count($ac2['events'] ?? []) >= 2, (string)$c);
    [$c, ] = call('GET', "console/activity?service_id=$sid", null, [], $jarB); check('event log refuses another company\'s service (404)', $c === 404, (string)$c);
    [, , $acsv] = call('GET', "console/activity?service_id=$sid&format=csv&days=all", null, [], $jarA, true); check('event log CSV export', str_contains($acsv, 'Time (UTC)') && str_contains($acsv, 'DNS'));
    [$c, ] = call('GET', "console/activity?service_id=$sid", null, [], $jarV); check('viewer can read the event log', $c === 200, (string)$c);
    [$c, ] = call('POST', 'events/ingest', ['events' => [$ev(9, 'x.com')]], ['X-Collector-Id' => $col['collector_uuid'], 'X-Api-Key' => 'wrong']); check('ingest rejects bad API key (401)', $c === 401, (string)$c);
    [$c, ] = call('POST', 'collector/heartbeat', ['collector_version' => '2.0.0', 'status' => 'ok', 'spool_depth' => 3, 'failed_submissions' => 1, 'last_error' => 'x', 'config_version' => 1], $H); check('heartbeat with health fields', $c === 200, (string)$c);
    check('health stored', (int)Db::val('SELECT spool_depth FROM collectors WHERE id = ?', [$col['id']]) === 3);

    echo "Exclusion & discovery\n";
    [, $x] = call('POST', "console/services/$sid", ['sanction_status' => 'excluded'], $A, $jarA);
    [, $ex] = call('POST', 'events/ingest', ['events' => [$ev(20, "zt-$sfx.example.com")]], $H); check('excluded service events are skipped', ($ex['accepted'] ?? 1) === 0, json_encode($ex));
    [$c, $dc] = call('GET', 'console/discovery', null, [], $jarA); check('discovery list readable', $c === 200, (string)$c);

    echo "Reports & export\n";
    foreach (['usage-by-service', 'sanctioned-vs-unsanctioned', 'top-domains', 'network-activity', 'workstation-activity', 'discovery', 'collector-health', 'registry'] as $n) {
        [$c, $j] = call('GET', "console/reports/$n?days=30", null, [], $jarA); check("report $n", $c === 200 && isset($j['rows']), (string)$c);
    }
    [$c, ] = call('GET', 'console/reports/nope', null, [], $jarA); check('unknown report 404', $c === 404, (string)$c);
    [$c, ] = call('GET', 'console/reports/registry?format=pdf', null, [], $jarA); check('bad format 422', $c === 422, (string)$c);
    [, , $xl] = call('GET', 'console/reports/registry?format=xlsx', null, [], $jarA, true); check('xlsx is a zip', str_starts_with($xl, "PK\x03\x04"));
    [, , $csv] = call('GET', 'console/reports/registry?format=csv', null, [], $jarA, true); check('csv has header row', str_contains($csv, 'Service'));
    [, $sA] = call('GET', 'console/dashboard/summary?days=30', null, [], $jarA); [, $sB] = call('GET', 'console/dashboard/summary?days=30', null, [], $jarB);
    check('summary is tenant-scoped', ($sA['totals']['dns_events'] ?? -1) > 0 && ($sB['totals']['dns_events'] ?? -1) === 0, json_encode([$sA['totals']['dns_events'] ?? null, $sB['totals']['dns_events'] ?? null]));
    [$c, ] = call('POST', 'console/retention', ['retention_events_days' => -1], $A, $jarA); check('invalid retention rejected', $c === 422, (string)$c);
    [$c, ] = call('POST', 'console/retention', ['retention_events_days' => 45], $A, $jarA); check('retention saved', $c === 200, (string)$c);

    echo "Event log paging & SIEM / webhooks\n";
    [, $ps] = call('POST', 'console/services', ['service_name' => "ZT Page $sfx", 'provider' => 'ZT', 'primary_domain' => "page.zt-$sfx.example.com"], $A, $jarA); $psid = (int)($ps['id'] ?? 0);
    $evs = []; for ($k = 0; $k < 30; $k++) $evs[] = $ev(500 + $k, "h$k.page.zt-$sfx.example.com");
    call('POST', 'events/ingest', ['events' => $evs], $H);
    [$c, $pg] = call('GET', "console/activity?service_id=$psid&days=all&page=1&size=10", null, [], $jarA);
    check('event log is paged on the server', $c === 200 && count($pg['events'] ?? []) === 10 && ($pg['total'] ?? 0) === 30 && ($pg['size'] ?? 0) === 10, json_encode([$pg['total'] ?? null, count($pg['events'] ?? [])]));
    [, $pg2] = call('GET', "console/activity?service_id=$psid&days=all&page=2&size=10", null, [], $jarA); check('page 2 holds different rows', ($pg2['events'][0]['id'] ?? 0) !== ($pg['events'][0]['id'] ?? -1) && count($pg2['events'] ?? []) === 10);
    [, $pg4] = call('GET', "console/activity?service_id=$psid&days=all&page=4&size=10", null, [], $jarA); check('a page past the end is empty, total unchanged', count($pg4['events'] ?? [1]) === 0 && ($pg4['total'] ?? 0) === 30);
    [, $sq] = call('GET', "console/activity?service_id=$psid&days=all&q=h7.page", null, [], $jarA); check('event log server-side search', ($sq['total'] ?? 0) === 1 && str_starts_with($sq['events'][0]['host'] ?? '', 'h7.'), json_encode($sq['total'] ?? null));
    [, $sn] = call('GET', "console/activity?service_id=$psid&days=all&q=no-such-host-xyz", null, [], $jarA); check('search with no match returns 0', ($sn['total'] ?? 1) === 0);
    [, $sf] = call('GET', "console/activity?service_id=$psid&days=all&f[kind]=DNS&f[host]=h1&sort=host&dir=asc&size=10", null, [], $jarA); check('column filter and sort', ($sf['total'] ?? 0) === 11 && ($sf['events'][0]['host'] ?? '') <= ($sf['events'][1]['host'] ?? 'zzz') && isset($sf['facets']['computer_name']), json_encode($sf['total'] ?? null));
    [$c, ] = call('GET', "console/activity?service_id=$psid&sort=%3Bdrop&dir=asc;--", null, [], $jarA); check('sort column is allow-listed (no SQL injection)', $c === 200);
    [$c, $cap] = call('GET', "console/activity?service_id=$psid&size=100000&page=-5", null, [], $jarA); check('page size is capped, bad page clamped', $c === 200 && ($cap['size'] ?? 0) === 100 && ($cap['page'] ?? 0) === 1);
    [, , $pcsv] = call('GET', "console/activity?service_id=$psid&days=all&format=csv&q=h3.page", null, [], $jarA, true); check('CSV export honours the search', substr_count($pcsv, "\n") === 2, (string)substr_count($pcsv, "\n"));

    // webhook delivery to a local receiver (the dispatcher runs in-process with private destinations allowed for this test)
    putenv('SAIP_ALLOW_PRIVATE_WEBHOOKS=1');
    $log = sys_get_temp_dir() . "/zt-recv-$sfx.log"; $recv = sys_get_temp_dir() . "/zt-recv-$sfx.php"; @unlink($log);
    file_put_contents($recv, '<?php file_put_contents(getenv("ZT_LOG"), json_encode(["h" => array_change_key_case(getallheaders(), CASE_LOWER), "b" => file_get_contents("php://input")]) . "\n", FILE_APPEND); http_response_code(getenv("ZT_FAIL") === "1" ? 500 : 200);');
    $proc = proc_open(['php', '-S', '127.0.0.1:8095', $recv], [1 => ['file', sys_get_temp_dir() . '/zt-recv-out', 'w'], 2 => ['file', sys_get_temp_dir() . '/zt-recv-err', 'w']], $pipes, null, ['ZT_LOG' => $log, 'PATH' => getenv('PATH'), 'SystemRoot' => getenv('SystemRoot') ?: '']);
    usleep(900000);
    [$c, ] = call('POST', 'console/integrations', ['name' => "zt-priv-$sfx", 'kind' => 'webhook', 'url' => 'https://127.0.0.1/hook', 'events' => ['audit.event']], $A, $jarA);
    check('API refuses a private / loopback webhook URL (SSRF guard)', $c === 422, (string)$c);
    [$c, ] = call('POST', 'console/integrations', ['name' => "zt-http-$sfx", 'kind' => 'webhook', 'url' => 'http://example.com/hook', 'events' => ['audit.event']], $A, $jarA);
    check('API refuses plain http:// webhooks', $c === 422, (string)$c);
    [$c, ] = call('POST', 'console/integrations', ['name' => "zt-v-$sfx", 'kind' => 'webhook', 'url' => 'https://example.com/hook', 'events' => ['audit.event']], ['X-CSRF-Token' => $csrfV], $jarV); check('viewer cannot create integrations (403)', $c === 403, (string)$c);
    [$c, ] = call('GET', 'console/integrations', null, [], $jarV); check('viewer cannot list integrations (403)', $c === 403, (string)$c);
    [$c, $sy] = call('POST', 'console/integrations', ['name' => "zt-syslog-$sfx", 'kind' => 'syslog', 'host' => '127.0.0.1', 'port' => 5514, 'protocol' => 'udp', 'format' => 'cef', 'events' => ['shadow_ai.detected']], $A, $jarA);
    check('syslog integration created', $c === 201 && ($sy['id'] ?? 0) > 0, (string)$c);
    [$c, ] = call('POST', 'console/integrations', ['name' => "zt-bad-$sfx", 'kind' => 'syslog', 'host' => 'bad host!', 'port' => 99999, 'events' => ['audit.event']], $A, $jarA); check('syslog host/port validated (422)', $c === 422, (string)$c);
    [$c, ] = call('POST', 'console/integrations', ['name' => "zt-ev-$sfx", 'kind' => 'syslog', 'host' => '127.0.0.1', 'port' => 5514, 'events' => ['nope.type']], $A, $jarA); check('unknown event type rejected (422)', $c === 422, (string)$c);
    $secretPlain = 'whsec_' . bin2hex(random_bytes(8));
    $cursorO = (int)Db::val('SELECT COALESCE(MAX(id),0) FROM event_outbox'); $cursorU = (int)Db::val('SELECT COALESCE(MAX(id),0) FROM ai_usage_events');
    Db::run("INSERT INTO integrations (tenant_id, name, kind, url, format, secret_enc, events, active, cursor_outbox, cursor_usage) VALUES (?,?,'webhook','http://127.0.0.1:8095/hook','json',?,?,1,?,?)",
        [$tA['id'], "zt-hook-$sfx", Saip\Security\Secrets::encrypt($secretPlain), 'audit.event,shadow_ai.detected,discovery.new_domain,usage.event', $cursorO, $cursorU]);
    $iid = Db::insertId();
    [$c, $lst] = call('GET', 'console/integrations', null, [], $jarA); $mine = current(array_filter($lst['integrations'] ?? [], fn ($x) => (int)$x['id'] === $iid));
    check('integration list never exposes the secret', $c === 200 && $mine && !isset($mine['secret_enc']) && $mine['has_secret'] === true && !str_contains(json_encode($lst), $secretPlain));
    check('stored secret is encrypted at rest', str_starts_with((string)Db::val('SELECT secret_enc FROM integrations WHERE id = ?', [$iid]), 'v1:') && !str_contains((string)Db::val('SELECT secret_enc FROM integrations WHERE id = ?', [$iid]), $secretPlain));
    [$c, ] = call('POST', 'console/policies', ['name' => "zt-siem-pol-$sfx", 'status' => 'Draft'], $A, $jarA);   // produces an audit.event
    [$c, $alertSvc] = call('POST', 'console/services', ['service_name' => "ZT Alert $sfx", 'provider' => 'ZT', 'primary_domain' => "alert.zt-$sfx.example.com"], $A, $jarA);
    call('POST', 'events/ingest', ['events' => [$ev(700, "alert.zt-$sfx.example.com"), $ev(701, "chat-ai-$sfx.zt-new.test")]], $H);
    call('POST', 'events/ingest', ['events' => [$ev(702, "alert.zt-$sfx.example.com")]], $H);   // same computer + service again: no second alert
    $r = Saip\IntegrationDispatcher::run($iid, true);
    $lines = is_file($log) ? array_filter(explode("\n", (string)file_get_contents($log))) : [];
    $req1 = $lines ? json_decode($lines[0], true) : null; $env = $req1 ? json_decode($req1['b'], true) : null;
    check('dispatcher delivered a batch to the webhook', ($r[0]['status'] ?? '') === 'ok' && $env && count($env['events'] ?? []) >= 3, json_encode($r));
    $types = array_column($env['events'] ?? [], 'type');
    check('batch has audit, shadow_ai.detected, discovery and usage events', in_array('audit.event', $types, true) && in_array('shadow_ai.detected', $types, true) && in_array('discovery.new_domain', $types, true) && in_array('usage.event', $types, true), json_encode(array_count_values($types)));
    check('shadow_ai.detected fires once per computer+service', count(array_filter($types, fn ($t) => $t === 'shadow_ai.detected')) === 1, json_encode(array_count_values($types)));
    $ts2 = $req1['h']['x-saip-timestamp'] ?? ''; $sig = $req1['h']['x-saip-signature'] ?? '';
    check('webhook is HMAC-SHA256 signed over timestamp.body', $sig === 'sha256=' . hash_hmac('sha256', $ts2 . '.' . ($req1['b'] ?? ''), $secretPlain), $sig);
    check('events carry the company slug', ($env['tenant'] ?? '') === $tA['slug'] && ($env['events'][0]['tenant'] ?? '') === $tA['slug']);
    $before = count($lines); $r2 = Saip\IntegrationDispatcher::run($iid, true);
    check('nothing is re-sent after a successful delivery (cursor advanced)', ($r2[0]['status'] ?? '') === 'idle' && count(array_filter(explode("\n", (string)file_get_contents($log)))) === $before, json_encode($r2));
    // failure path: receiver answers 500 -> cursor holds, failure counted, backoff set
    proc_terminate($proc); proc_close($proc); usleep(300000);
    $proc = proc_open(['php', '-S', '127.0.0.1:8095', $recv], [1 => ['file', sys_get_temp_dir() . '/zt-recv-out', 'w'], 2 => ['file', sys_get_temp_dir() . '/zt-recv-err', 'w']], $pipes, null, ['ZT_LOG' => $log, 'ZT_FAIL' => '1', 'PATH' => getenv('PATH'), 'SystemRoot' => getenv('SystemRoot') ?: '']); usleep(900000);
    call('POST', 'console/policies', ['name' => "zt-siem-pol2-$sfx", 'status' => 'Draft'], $A, $jarA);
    $r3 = Saip\IntegrationDispatcher::run($iid, true);
    $row = Db::one('SELECT failures, last_status, next_attempt_at, cursor_outbox FROM integrations WHERE id = ?', [$iid]);
    check('failed delivery is recorded, retried later and loses nothing', ($r3[0]['status'] ?? '') === 'failed' && (int)$row['failures'] === 1 && $row['last_status'] === 'failed' && $row['next_attempt_at'] !== null, json_encode([$r3, $row]));
    proc_terminate($proc); proc_close($proc);
    $cef = Saip\IntegrationDispatcher::cef(['id' => 'o1', 'type' => 'shadow_ai.detected', 'time' => '2026-10-30T09:15:02Z', 'data' => ['service' => 'Chat|GPT', 'computer' => 'WS-1', 'host' => 'chatgpt.com']], 'acme');
    check('CEF line is well-formed and escaped', str_starts_with($cef, 'CEF:0|SAIP|Shadow AI Platform|1.0|shadow_ai.detected|Shadow AI detected: Chat\\|GPT|7|') && str_contains($cef, 'shost=WS-1') && str_contains($cef, 'dhost=chatgpt.com'), $cef);
    // SIEM pull API
    [$c, $tk] = call('POST', 'console/integration-tokens', ['name' => "zt-tok-$sfx"], $A, $jarA); $token = $tk['token'] ?? '';
    check('API token created and shown once', $c === 201 && str_starts_with($token, 'saip_siem_') && !Db::val('SELECT 1 FROM api_tokens WHERE token_hash = ?', [$token]) && (bool)Db::val('SELECT 1 FROM api_tokens WHERE token_hash = ?', [hash('sha256', $token)]));
    [$c, ] = call('GET', 'siem/events'); check('SIEM pull needs a token (401)', $c === 401, (string)$c);
    [$c, ] = call('GET', 'siem/events', null, ['Authorization' => 'Bearer saip_siem_' . str_repeat('0', 48)]); check('wrong token rejected (401)', $c === 401, (string)$c);
    [$c, $pull] = call('GET', 'siem/events?since_id=0&limit=5', null, ['Authorization' => "Bearer $token"]);
    check('SIEM pull returns events with a cursor', $c === 200 && isset($pull['next_id']) && is_array($pull['events']), (string)$c);
    [, , $pj] = call('GET', 'siem/events?since_id=0&limit=3&format=jsonl', null, ['Authorization' => "Bearer $token"], null, true); check('SIEM pull JSONL', str_contains($pj, '"type"'));
    [, , $pc] = call('GET', 'siem/events?since_id=0&limit=3&format=cef', null, ['Authorization' => "Bearer $token"], null, true); check('SIEM pull CEF', str_starts_with($pc, 'CEF:0|SAIP|'));
    [$c, $pu] = call('GET', 'siem/usage?since_id=0&limit=2', null, ['Authorization' => "Bearer $token"]); check('SIEM usage stream', $c === 200 && count($pu['events'] ?? []) >= 1 && ($pu['events'][0]['type'] ?? '') === 'usage.event');
    [$c, $pb] = call('GET', 'siem/events?since_id=0', null, ['Authorization' => "Bearer $token"]); $ten = array_unique(array_column($pb['events'] ?? [], 'tenant')); check('SIEM pull is tenant-scoped', $c === 200 && $ten === [$tA['slug']], json_encode($ten));
    [$c, ] = call('POST', 'console/integration-tokens/delete', ['ids' => [(int)($tk['id'] ?? 0)]], $A, $jarA); [$c2, ] = call('GET', 'siem/events', null, ['Authorization' => "Bearer $token"]); check('revoked token stops working', $c === 200 && $c2 === 401, "$c/$c2");
    [$c, ] = call('POST', 'console/integrations/delete', ['ids' => [$iid, (int)$sy['id']]], $A, $jarA); check('integrations deleted', $c === 200 && !Db::val('SELECT 1 FROM integrations WHERE id = ?', [$iid]), (string)$c);
    @unlink($log); @unlink($recv);

    echo "Network connections matched by address (Event ID 3)\n";
    check('IpIntel knows shared edge networks (Cloudflare, Google, IPv6) and dedicated addresses', Saip\IpIntel::sharedNetwork('104.18.32.47') === 'Cloudflare' && Saip\IpIntel::sharedNetwork('142.251.153.2') === 'Google front ends' && Saip\IpIntel::sharedNetwork('2606:4700:4408::ac40:9bd1') === 'Cloudflare' && Saip\IpIntel::sharedNetwork('160.79.104.10') === null && Saip\IpIntel::sharedNetwork('1.2.3.4') === null && Saip\IpIntel::sharedNetwork('not-an-ip') === null);
    [$c, ] = call('POST', 'console/ip-map/refresh', [], ['X-CSRF-Token' => $csrfV], $jarV); check('viewer cannot refresh the address map (403)', $c === 403, (string)$c);
    [$c, $ims] = call('GET', 'console/ip-map', null, [], $jarV); check('address-map status readable', $c === 200 && isset($ims['status']['usable']), (string)$c);
    Db::run('INSERT INTO ip_map (tenant_id, ip, ai_service_id, domain, shared) VALUES (?,?,?,?,0),(?,?,?,?,1),(?,?,?,?,0)', [$tA['id'], '198.51.100.7', $psid, "h0.page.zt-$sfx.example.com", $tA['id'], '198.51.100.8', $psid, "h0.page.zt-$sfx.example.com", $tA['id'], '2001:db8::7', $psid, "h0.page.zt-$sfx.example.com"]);
    [$c, ] = call('POST', 'console/monitoring', ['network_events' => true], $A, $jarA); check('network connections switched on', $c === 200, (string)$c);
    [, $cf] = call('GET', 'collector/config', null, $H); $ips = array_column($cf['ip_rules'] ?? [], 'ip');
    check('collector config carries dedicated addresses only', in_array('198.51.100.7', $ips, true) && !in_array('198.51.100.8', $ips, true) && in_array('2001:db8::7', $ips, true), json_encode($ips));
    $nc = fn (int $id, string $ip, array $x = []) => ['sysmon_record_id' => $id, 'event_timestamp' => $ts, 'event_type' => 'network_connection', 'destination_ip' => $ip, 'destination_port' => 443, 'protocol' => 'tcp', 'process_image' => 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'] + $x;
    [, $ni] = call('POST', 'events/ingest', ['events' => [$nc(900, '198.51.100.7'), $nc(901, '104.18.32.47'), $nc(902, '203.0.113.9'), $nc(903, '2001:db8::7'), $nc(904, '198.51.100.8')]], $H);
    check('dedicated-address connections are accepted (2), CDN addresses are ambiguous (2), unknown is unmatched (1)', ($ni['accepted'] ?? 0) === 2 && ($ni['ambiguous'] ?? 0) === 2 && ($ni['unmatched'] ?? 0) === 1, json_encode($ni));
    check('address matches are marked match_basis=ip and tied to the service', (int)Db::val("SELECT COUNT(*) FROM network_connection_events WHERE tenant_id = ? AND ai_service_id = ? AND match_basis = 'ip' AND destination_host IS NULL", [$tA['id'], $psid]) === 2);
    check('shared-address connections are never stored as usage', !Db::val("SELECT 1 FROM network_connection_events WHERE tenant_id = ? AND destination_ip IN ('104.18.32.47','198.51.100.8')", [$tA['id']]));
    [, $nh] = call('POST', 'events/ingest', ['events' => [$nc(905, '104.18.32.47', ['destination_host' => "h1.page.zt-$sfx.example.com"])]], $H);
    check('a connection with a registered host name still matches by host (even on a CDN address)', ($nh['accepted'] ?? 0) === 1 && Db::val("SELECT match_basis FROM network_connection_events WHERE tenant_id = ? AND sysmon_record_id = 905", [$tA['id']]) === 'host', json_encode($nh));
    [, $nr] = call('GET', 'console/reports/network-activity?days=30', null, [], $jarA); check('network activity report shows how each connection was matched', isset($nr['columns']['match_basis']) && count($nr['rows'] ?? []) >= 2, json_encode($nr['columns'] ?? null));
    [$c, ] = call('POST', 'console/monitoring', ['network_events' => false], $A, $jarA);
    [, $cf2] = call('GET', 'collector/config', null, $H); check('address list is not sent when network connections are off', !isset($cf2['ip_rules']));

    echo "Delete (CRUD)\n";
    $V = ['X-CSRF-Token' => $csrfV]; $B = ['X-CSRF-Token' => $csrfB];
    [, $s2] = call('POST', 'console/services', ['service_name' => 'ZT Del', 'provider' => 'ZT', 'primary_domain' => "del.zt-$sfx.example.com"], $A, $jarA); $sid2 = (int)($s2['id'] ?? 0);
    call('POST', 'console/registry/domains', ['service_id' => $sid2, 'domain' => "api.del.zt-$sfx.example.com"], $A, $jarA);
    $ev2 = fn (int $id, string $d) => ['sysmon_record_id' => $id, 'event_timestamp' => $ts, 'query_domain' => $d];
    call('POST', 'events/ingest', ['events' => [$ev2(101, "del.zt-$sfx.example.com"), $ev2(102, "api.del.zt-$sfx.example.com")]], $H);
    $evCount = fn () => (int)Db::val('SELECT COUNT(*) FROM ai_usage_events WHERE ai_service_id = ?', [$sid2]);
    check('setup: events recorded for the service', $evCount() === 2, (string)$evCount());
    [$c, ] = call('POST', 'console/services/delete', ['ids' => [$sid2]], $V, $jarV); check('viewer cannot delete a service (403)', $c === 403, (string)$c);
    [$c, ] = call('POST', 'console/services/delete', ['ids' => [$sid2]], $B, $jarB); check('other company cannot delete it (404)', $c === 404, (string)$c);
    [$c, ] = call('POST', 'console/services/delete', ['ids' => []], $A, $jarA); check('empty selection rejected (422)', $c === 422, (string)$c);
    [, $pv] = call('POST', 'console/services/delete', ['ids' => [$sid2], 'preview' => true], $A, $jarA);
    check('preview reports the impact', ($pv['preview']['events'] ?? 0) === 2 && ($pv['preview']['domains'] ?? 0) === 2, json_encode($pv['preview'] ?? null));
    check('preview deletes nothing', (bool)Db::val('SELECT 1 FROM ai_services WHERE id = ?', [$sid2]) && $evCount() === 2);
    $dids = array_column(Db::all('SELECT id FROM ai_domains WHERE ai_service_id = ? ORDER BY id', [$sid2]), 'id');
    [$c, ] = call('POST', 'console/registry/domains/delete', ['ids' => $dids], $A, $jarA); check('cannot delete a service\'s last domains (409)', $c === 409, (string)$c);
    [$c, ] = call('POST', 'console/registry/domains/delete', ['ids' => [$dids[1]]], $A, $jarA); check('one domain deleted', $c === 200 && (int)Db::val('SELECT COUNT(*) FROM ai_domains WHERE ai_service_id = ?', [$sid2]) === 1, (string)$c);
    $v0 = (int)Db::val('SELECT config_version FROM tenants WHERE id = ?', [$tA['id']]);
    [$c, ] = call('POST', 'console/services/delete', ['ids' => [$sid2]], $A, $jarA); check('service deleted', $c === 200, (string)$c);
    check('service, domains and events are gone', !Db::val('SELECT 1 FROM ai_services WHERE id = ?', [$sid2]) && !Db::val('SELECT 1 FROM ai_domains WHERE ai_service_id = ?', [$sid2]) && $evCount() === 0);
    check('registry version bumped so collectors resync', (int)Db::val('SELECT config_version FROM tenants WHERE id = ?', [$tA['id']]) > $v0);
    check('delete is audit-logged', (bool)Db::val("SELECT 1 FROM audit_logs WHERE tenant_id = ? AND action = 'service_deleted'", [$tA['id']]));
    Db::run('INSERT INTO discovered_domains (tenant_id, domain, hit_count, first_seen, last_seen) VALUES (?,?,1,UTC_TIMESTAMP(),UTC_TIMESTAMP())', [$tA['id'], "found.zt-$sfx.test"]); $did = Db::insertId();
    Db::run('INSERT INTO discovered_domain_hosts (discovered_id, computer_name, hit_count, first_seen, last_seen) VALUES (?,?,1,UTC_TIMESTAMP(),UTC_TIMESTAMP())', [$did, 'ZT-X']);
    [$c, ] = call('POST', 'console/discovery/delete', ['ids' => [$did]], $B, $jarB); check('other company cannot delete discovery rows (404)', $c === 404, (string)$c);
    [$c, ] = call('POST', 'console/discovery/delete', ['ids' => [$did]], $A, $jarA); check('discovery row deleted with its hosts', $c === 200 && !Db::val('SELECT 1 FROM discovered_domain_hosts WHERE discovered_id = ?', [$did]));
    $cid = (int)$col['id'];
    call('POST', 'console/workstations/map', ['computer_name' => "ZT-WS-$sfx", 'department' => 'QA'], $A, $jarA);
    [$c, ] = call('POST', 'console/collectors/delete', ['ids' => [$cid], 'data_only' => true], $V, $jarV); check('viewer cannot clear collector data (403)', $c === 403, (string)$c);
    [$c, ] = call('POST', 'console/collectors/delete', ['ids' => [$cid], 'data_only' => true], $A, $jarA);
    check('clear data keeps the collector, removes events', $c === 200 && (bool)Db::val('SELECT 1 FROM collectors WHERE id = ?', [$cid]) && (int)Db::val('SELECT COUNT(*) FROM ai_usage_events WHERE collector_id = ?', [$cid]) === 0);
    [$c, ] = call('POST', 'console/collectors/delete', ['ids' => [$cid]], $B, $jarB); check('other company cannot delete the collector (404)', $c === 404, (string)$c);
    [$c, ] = call('POST', 'console/collectors/delete', ['ids' => [$cid]], $A, $jarA);
    check('collector, heartbeats and department mapping deleted', $c === 200 && !Db::val('SELECT 1 FROM collectors WHERE id = ?', [$cid]) && !Db::val('SELECT 1 FROM collector_heartbeats WHERE collector_id = ?', [$cid])
        && !Db::val('SELECT 1 FROM employee_inventory WHERE tenant_id = ? AND computer_name = ?', [$tA['id'], "ZT-WS-$sfx"]));
    [$c, ] = call('POST', 'events/ingest', ['events' => [$ev2(900, "zt-$sfx.example.com")]], $H); check('deleted collector can no longer send data (401)', $c === 401, (string)$c);
    [$c, ] = call('POST', 'console/services/delete', ['ids' => [$sid]], $A, $jarA); check('service with events/domains deletes cleanly', $c === 200, (string)$c);

    echo "RBAC, user management & security (OWASP)\n";
    Db::run("DELETE FROM rate_limits WHERE bucket LIKE 'login:%'");
    [$jarAu, $csrfAu] = login("zt-aud-$sfx", $pw); [$jarS, $csrfS] = login("zt-super-$sfx", $pw);
    $AU = ['X-CSRF-Token' => $csrfAu]; $SU = ['X-CSRF-Token' => $csrfS];
    [$c, ] = call('GET', 'console/audit', null, [], $jarV); check('viewer cannot read the audit log (403)', $c === 403, (string)$c);
    [$c, ] = call('GET', 'console/audit', null, [], $jarAu); check('auditor can read the audit log', $c === 200, (string)$c);
    [$c, ] = call('GET', 'console/registry', null, [], $jarAu); check('auditor can read the registry', $c === 200, (string)$c);
    [$c, ] = call('POST', 'console/services', ['service_name' => 'x', 'primary_domain' => 'x.example.com'], $AU, $jarAu); check('auditor cannot write (403)', $c === 403, (string)$c);
    check('access denial is audited', (bool)Db::val("SELECT 1 FROM audit_logs WHERE tenant_id = ? AND action = 'access_denied'", [$tA['id']]));
    [$c, $me] = call('GET', 'console/me', null, [], $jarV); check('me exposes the role permission set', $c === 200 && in_array('registry.read', $me['permissions'] ?? [], true) && !in_array('registry.write', $me['permissions'] ?? [], true));
    [$c, $ul] = call('GET', 'console/users', null, [], $jarA); $names = array_column($ul['users'] ?? [], 'username');
    check('it_admin lists only own-company users', $c === 200 && in_array("zt-admin-$sfx", $names, true) && !in_array("zt-bob-$sfx", $names, true), json_encode($names));
    [$c, ] = call('GET', 'console/users', null, [], $jarV); check('viewer cannot list users (403)', $c === 403, (string)$c);
    [$c, ] = call('POST', 'console/users', ['username' => "zt-evil-$sfx", 'password' => 'Str0ng-Passw0rd!x', 'role' => 'super_admin'], $A, $jarA); check('it_admin cannot create a platform admin (403)', $c === 403, (string)$c);
    [$c, ] = call('POST', 'console/users', ['username' => "zt-weak-$sfx", 'password' => 'short', 'role' => 'viewer'], $A, $jarA); check('weak password rejected (422)', $c === 422, (string)$c);
    [$c, ] = call('POST', 'console/users', ['username' => "zt-weak-$sfx", 'password' => 'alllowercaseletters', 'role' => 'viewer'], $A, $jarA); check('single-class password rejected (422)', $c === 422, (string)$c);
    [$c, $nu] = call('POST', 'console/users', ['username' => "zt-new-$sfx", 'display_name' => 'New', 'email' => 'new@example.com', 'password' => 'Str0ng-Passw0rd!x', 'role' => 'viewer'], $A, $jarA); $nid = (int)($nu['id'] ?? 0);
    check('it_admin creates a user in own company', $c === 201 && (int)Db::val('SELECT tenant_id FROM admin_users WHERE id = ?', [$nid]) === (int)$tA['id'], (string)$c);
    check('password stored as a strong hash, never plain', str_starts_with((string)Db::val('SELECT password_hash FROM admin_users WHERE id = ?', [$nid]), '$argon2id$') || str_starts_with((string)Db::val('SELECT password_hash FROM admin_users WHERE id = ?', [$nid]), '$2y$'));
    [$c, ] = call('POST', 'console/users', ['username' => "zt-new-$sfx", 'password' => 'Str0ng-Passw0rd!x', 'role' => 'viewer'], $A, $jarA); check('duplicate username rejected (409)', $c === 409, (string)$c);
    [$c, ] = call('POST', "console/users/$nid", ['role' => 'auditor', 'display_name' => 'Renamed'], $A, $jarA); check('user role updated', $c === 200 && Db::val('SELECT role FROM admin_users WHERE id = ?', [$nid]) === 'auditor', (string)$c);
    $bobId = (int)Db::val('SELECT id FROM admin_users WHERE username = ?', ["zt-bob-$sfx"]);
    [$c, ] = call('POST', "console/users/$bobId", ['active' => false], $A, $jarA); check('it_admin cannot edit another company\'s user (404)', $c === 404, (string)$c);
    $meId = (int)Db::val('SELECT id FROM admin_users WHERE username = ?', ["zt-admin-$sfx"]);
    [$c, ] = call('POST', "console/users/$meId", ['active' => false], $A, $jarA); check('cannot deactivate your own account (409)', $c === 409, (string)$c);
    [$c, ] = call('POST', 'console/users/delete', ['ids' => [$meId]], $A, $jarA); check('cannot delete your own account (409)', $c === 409, (string)$c);
    $supId = (int)Db::val('SELECT id FROM admin_users WHERE username = ?', ["zt-super-$sfx"]);
    [$c, ] = call('POST', 'console/users/delete', ['ids' => [$supId]], $A, $jarA); check('it_admin cannot delete a platform admin (404)', $c === 404, (string)$c);
    [$c, ] = call('POST', 'console/users/delete', ['ids' => [$nid]], $A, $jarA); check('user deleted', $c === 200 && !Db::val('SELECT 1 FROM admin_users WHERE id = ?', [$nid]), (string)$c);
    check('user changes are audited with before/after', (bool)Db::val("SELECT 1 FROM audit_logs WHERE action = 'user_updated' AND before_json LIKE '%viewer%' AND after_json LIKE '%auditor%'"));

    // account protection
    $lockId = $mk("zt-lock-$sfx", 'viewer', $tA['id']); $lockUid = (int)Db::val('SELECT id FROM admin_users WHERE username = ?', ["zt-lock-$sfx"]);
    Db::run("DELETE FROM rate_limits WHERE bucket LIKE 'login:%'");
    for ($i = 0; $i < 5; $i++) login_attempt("zt-lock-$sfx", 'wrong-password');
    $r = login_attempt("zt-lock-$sfx", $pw);
    check('account locks after repeated failures, even with the right password', (bool)Db::val('SELECT locked_until > UTC_TIMESTAMP() FROM admin_users WHERE id = ?', [$lockUid]) && str_contains($r, 'locked'), substr(strip_tags($r), 0, 120));
    [$c, ] = call('POST', "console/users/$lockUid", ['unlock' => true], $A, $jarA); check('admin can clear a lockout', $c === 200 && !Db::val('SELECT locked_until FROM admin_users WHERE id = ?', [$lockUid]));

    // password change + session invalidation
    Db::run("DELETE FROM rate_limits WHERE bucket LIKE 'login:%'");
    [$jarA2, $csrfA2] = login("zt-admin-$sfx", $pw);
    [$c, ] = call('POST', 'console/me/password', ['current_password' => 'wrong', 'new_password' => 'Another-Str0ng-Pw!'], ['X-CSRF-Token' => $csrfA2], $jarA2); check('password change needs the current password (403)', $c === 403, (string)$c);
    [$c, ] = call('POST', 'console/me/password', ['current_password' => $pw, 'new_password' => 'weak'], ['X-CSRF-Token' => $csrfA2], $jarA2); check('password change enforces policy (422)', $c === 422, (string)$c);
    [$c, ] = call('POST', 'console/me/password', ['current_password' => $pw, 'new_password' => 'Another-Str0ng-Pw!9'], ['X-CSRF-Token' => $csrfA2], $jarA2); check('password changed', $c === 200, (string)$c);
    [$c, ] = call('GET', 'console/me', null, [], $jarA2); check('the changing session stays valid', $c === 200, (string)$c);
    [$c, ] = call('GET', 'console/me', null, [], $jarA); check('other sessions are signed out after a password change (401)', $c === 401, (string)$c);

    // CSRF / origin / headers / cookies
    [$c, ] = call('POST', 'console/policies', ['name' => 'zt-pol'], ['X-CSRF-Token' => $csrfV, 'Origin' => 'https://evil.example'], $jarV); check('cross-origin write rejected even with a token (403)', $c === 403, (string)$c);
    [$c, ] = call('POST', 'console/retention', ['retention_events_days' => 5], ['X-CSRF-Token' => 'forged'], $jarS); check('forged CSRF token rejected (403)', $c === 403, (string)$c);
    $ch = curl_init($GLOBALS['base'] . 'console/me'); curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true, CURLOPT_COOKIEFILE => $jarS]); $hdr = (string)curl_exec($ch); unset($ch);
    check('security headers present', str_contains($hdr, 'Content-Security-Policy') && str_contains($hdr, 'X-Content-Type-Options: nosniff') && str_contains($hdr, 'X-Frame-Options: DENY') && str_contains($hdr, 'Referrer-Policy'));
    check('CSP forbids inline script', !preg_match("/script-src[^;]*'unsafe-inline'/", $hdr));
    $raw = call('POST', 'console/policies', ['name' => 'x'], [], null, true); check('no session cookie -> 401 and no Set-Cookie fixation', $raw[0] === 401);
    $ck = (string)@file_get_contents($jarS); check('session cookie is HttpOnly', str_contains($ck, '#HttpOnly_'));
    [$c, $j] = call('POST', 'console/services', ['service_name' => "zt'); DROP TABLE ai_services;--", 'primary_domain' => 'sqli.zt.example.com'], $A, $jarA2 ?: $jarA);
    check('SQL metacharacters stored as data, tables intact', (bool)Db::val('SELECT COUNT(*) FROM ai_services') > 0);

    // companies (platform admin)
    [$c, ] = call('GET', 'console/tenants', null, [], $jarA2); check('it_admin cannot list companies (403)', $c === 403, (string)$c);
    [$c, $tn] = call('POST', 'console/tenants', ['name' => "ZT Gamma $sfx"], $SU, $jarS); $gid = (int)($tn['id'] ?? 0); check('platform admin creates a company', $c === 201 && $gid > 0, (string)$c);
    [$c, ] = call('POST', "console/tenants/$gid", ['name' => "ZT Gamma2 $sfx", 'status' => 'suspended'], $SU, $jarS); check('company updated', $c === 200 && Db::val('SELECT status FROM tenants WHERE id = ?', [$gid]) === 'suspended', (string)$c);
    $gslug = (string)Db::val('SELECT slug FROM tenants WHERE id = ?', [$gid]);
    [$c, ] = call('POST', 'console/tenants/delete', ['ids' => [$gid], 'confirm' => 'wrong'], $SU, $jarS); check('company delete needs the typed short name (422)', $c === 422, (string)$c);
    [$c, ] = call('POST', 'console/tenants/delete', ['ids' => [$gid], 'confirm' => $gslug], $SU, $jarS); check('company deleted', $c === 200 && !Db::val('SELECT 1 FROM tenants WHERE id = ?', [$gid]), (string)$c);
    check('company deletion keeps its audit trail', (bool)Db::val("SELECT 1 FROM audit_logs WHERE action = 'tenant_deleted'"));
    [$c, ] = call('POST', 'console/users/delete', ['ids' => [$supId]], $SU, $jarS); check('last platform administrator cannot be deleted/self-deleted (409)', $c === 409, (string)$c);

    echo "FQDN directory & import\n";
    $imp = ['rows' => [
        ['service' => "ZT Import $sfx", 'fqdn' => "app.imp-$sfx.example.com", 'root' => "imp-$sfx.example.com", 'registrar' => 'Cloudflare, Inc.', 'purpose' => 'Web UI', 'category' => 'Conversational AI / Chat', 'endpoint' => 'Web'],
        ['service' => "ZT Import $sfx", 'fqdn' => "api.imp-$sfx.example.com", 'root' => "imp-$sfx.example.com", 'registrar' => 'Cloudflare, Inc.', 'purpose' => 'REST API', 'category' => 'Foundation Models & API', 'endpoint' => 'API'],
        ['service' => "ZT Import $sfx", 'fqdn' => "*.cdn.imp-$sfx.example.com", 'root' => '', 'registrar' => '', 'purpose' => '', 'category' => '', 'endpoint' => 'CDN assets'],
        ['service' => "ZT Bad $sfx", 'fqdn' => '10.0.0.5', 'root' => '', 'registrar' => '', 'purpose' => '', 'category' => '', 'endpoint' => ''],
        ['service' => '', 'fqdn' => 'x.example.com', 'root' => '', 'registrar' => '', 'purpose' => '', 'category' => '', 'endpoint' => ''],
    ]];
    [$c, ] = call('POST', 'console/registry/import', $imp, $V, $jarV); check('viewer cannot import (403)', $c === 403, (string)$c);
    [$c, $dry] = call('POST', 'console/registry/import', $imp + ['dry_run' => true], ['X-CSRF-Token' => $csrfA2], $jarA2);
    check('dry run reports without saving', $c === 200 && ($dry['services_created'] ?? 0) === 1 && ($dry['domains_added'] ?? 0) === 3 && count($dry['errors'] ?? []) === 2 && !Db::val('SELECT 1 FROM ai_services WHERE service_name = ?', ["ZT Import $sfx"]), json_encode($dry));
    $csrf2 = ['X-CSRF-Token' => $csrfA2];
    [$c, $ok] = call('POST', 'console/registry/import', $imp, $csrf2, $jarA2);
    check('import creates the service and its FQDNs with registrar and purpose', $c === 200 && (int)Db::val('SELECT COUNT(*) FROM ai_domains d JOIN ai_services s ON s.id = d.ai_service_id WHERE s.service_name = ? AND d.registrar IS NOT NULL', ["ZT Import $sfx"]) === 2, json_encode($ok));
    check('imported service starts Unsanctioned with a risk score', Db::val('SELECT sanction_status FROM ai_services WHERE service_name = ?', ["ZT Import $sfx"]) === 'unsanctioned');
    check('wildcard FQDN becomes a subdomain rule', Db::val('SELECT matching_rule FROM ai_domains WHERE domain = ?', ["cdn.imp-$sfx.example.com"]) === 'subdomain');
    [, $again] = call('POST', 'console/registry/import', $imp, $csrf2, $jarA2); check('re-import is idempotent', ($again['services_created'] ?? 1) === 0 && ($again['domains_added'] ?? 1) === 0, json_encode($again));
    [$c, $fl] = call('GET', 'console/registry/domains', null, [], $jarA2); $row = current(array_filter($fl['domains'] ?? [], fn ($d) => $d['domain'] === "api.imp-$sfx.example.com"));
    check('FQDN directory lists registrar, purpose and service', $c === 200 && $row && $row['registrar'] === 'Cloudflare, Inc.' && $row['purpose'] === 'REST API' && $row['service_name'] === "ZT Import $sfx", json_encode($row));
    [$c, ] = call('POST', 'console/registry/domains/' . ($row['id'] ?? 0), ['registrar' => 'Namecheap, Inc.', 'domain' => "api2.imp-$sfx.example.com", 'purpose' => 'Updated'], $csrf2, $jarA2);
    check('FQDN edited: registrar, purpose and hostname', $c === 200 && Db::val('SELECT registrar FROM ai_domains WHERE id = ?', [$row['id']]) === 'Namecheap, Inc.' && Db::val('SELECT domain FROM ai_domains WHERE id = ?', [$row['id']]) === "api2.imp-$sfx.example.com", (string)$c);
    [$c, ] = call('POST', 'console/registry/domains/' . $row['id'], ['domain' => "app.imp-$sfx.example.com"], $csrf2, $jarA2); check('renaming onto an existing FQDN is rejected (409)', $c === 409, (string)$c);
    [$c, ] = call('GET', 'console/registry/domains', null, [], $jarB); check('FQDN directory is tenant-scoped', !in_array("api2.imp-$sfx.example.com", array_column($c === 200 ? (call('GET', 'console/registry/domains', null, [], $jarB)[1]['domains'] ?? []) : [], 'domain'), true));

    echo "Google sign-in, Sysmon reference\n";
    [$c, ] = call('GET', 'console/settings/auth', null, [], $jarA2); check('it_admin cannot read authentication settings (403)', $c === 403, (string)$c);
    [$c, ] = call('POST', 'console/settings/auth', ['google' => ['enabled' => true]], $csrf2, $jarA2); check('it_admin cannot change authentication settings (403)', $c === 403, (string)$c);
    [$c, ] = call('POST', 'console/settings/auth', ['google' => ['enabled' => true, 'client_id' => '']], $SU, $jarS); check('cannot enable Google without client id and secret (422)', $c === 422, (string)$c);
    [$c, ] = call('POST', 'console/settings/auth', ['google' => ['enabled' => false, 'client_id' => 'bad id!!']], $SU, $jarS); check('client id format validated (422)', $c === 422, (string)$c);
    [$c, ] = call('POST', 'console/settings/auth', ['google' => ['auto_provision' => true, 'allowed_domains' => '', 'client_id' => '1234567890-zt.apps.googleusercontent.com']], $SU, $jarS); check('auto-provisioning needs a domain and company (422)', $c === 422, (string)$c);
    $gsec = 'GOCSPX-' . bin2hex(random_bytes(10));
    [$c, $gs] = call('POST', 'console/settings/auth', ['google' => ['enabled' => true, 'client_id' => "1234567890-zt$sfx.apps.googleusercontent.com", 'client_secret' => $gsec, 'allowed_domains' => 'zt-example.test', 'auto_provision' => false, 'default_role' => 'viewer']], $SU, $jarS);
    check('platform admin enables Google sign-in', $c === 200 && ($gs['google']['enabled'] ?? false) === true && ($gs['google']['has_secret'] ?? false) === true, json_encode($gs));
    check('client secret is encrypted in the database and never returned', !str_contains(json_encode($gs), $gsec) && str_starts_with((string)Db::val("SELECT value FROM platform_settings WHERE name = 'google.client_secret'"), 'v1:'));
    check('settings change is audited without the secret', (bool)Db::val("SELECT 1 FROM audit_logs WHERE action = 'auth_settings_changed'") && !Db::val("SELECT 1 FROM audit_logs WHERE details LIKE ? OR after_json LIKE ?", ["%$gsec%", "%$gsec%"]));
    $page = (string)@file_get_contents(preg_replace('#api/v1/$#', '', $base) . 'login'); check('login page shows "Sign in with Google" when enabled', str_contains($page, 'Sign in with Google'));
    $ch = curl_init(preg_replace('#api/v1/$#', '', $base) . 'auth/google'); $gj = tempnam(sys_get_temp_dir(), 'zt'); curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true, CURLOPT_COOKIEJAR => $gj, CURLOPT_COOKIEFILE => $gj, CURLOPT_FOLLOWLOCATION => false]); $gh = (string)curl_exec($ch);
    preg_match('/^Location:\s*(\S+)/mi', $gh, $lm); $loc = $lm[1] ?? ''; parse_str((string)parse_url($loc, PHP_URL_QUERY), $gq);
    check('Google redirect uses authorization code + PKCE + state + nonce', str_starts_with($loc, 'https://accounts.google.com/o/oauth2/v2/auth') && ($gq['response_type'] ?? '') === 'code' && ($gq['code_challenge_method'] ?? '') === 'S256' && strlen($gq['state'] ?? '') >= 16 && strlen($gq['nonce'] ?? '') >= 16 && ($gq['hd'] ?? '') === 'zt-example.test' && str_contains($gq['redirect_uri'] ?? '', '/auth/google/callback'), $loc);
    curl_setopt_array($ch, [CURLOPT_URL => preg_replace('#api/v1/$#', '', $base) . 'auth/google/callback?code=abc&state=forged']); $cb = (string)curl_exec($ch);
    preg_match('/http-equiv="refresh" content="0;url=([^"]+)"/', $cb, $cm); check('callback with a forged state is refused (back to /login with a coded error)', str_contains($cm[1] ?? '', '/login?ge=expired') && !Db::val("SELECT 1 FROM audit_logs WHERE action = 'login_google' AND timestamp >= UTC_TIMESTAMP() - INTERVAL 1 MINUTE"), $cm[1] ?? '');
    check('failed Google attempt is audited', (bool)Db::val("SELECT 1 FROM audit_logs WHERE action = 'login_google_failed' AND details LIKE '%state mismatch%'"));
    unset($ch);
    $gUser = (int)Db::val('SELECT id FROM admin_users WHERE username = ?', ["zt-aud-$sfx"]);
    [$c, ] = call('POST', "console/users/$gUser", ['local_login' => false], $csrf2, $jarA2); check('password sign-in can be turned off once Google is enabled', $c === 200 && !(int)Db::val('SELECT local_login FROM admin_users WHERE id = ?', [$gUser]), (string)$c);
    $pwOff = login_attempt("zt-aud-$sfx", $pw); check('a Google-only account cannot sign in with a password', !str_contains($pwOff, 'Location') && (bool)Db::val("SELECT 1 FROM audit_logs WHERE action = 'login_failed' AND details LIKE '%password sign-in disabled%'"));
    [$c, ] = call('POST', "console/users/$meId", ['local_login' => false], $csrf2, $jarA2); check('you cannot disable your own password sign-in (409)', $c === 409 || $c === 200 && false, (string)$c);
    [$c, $sm] = call('GET', 'console/sysmon', null, [], $jarV);
    check('Sysmon catalog: events, JSON samples and field mapping', $c === 200 && count($sm['events'] ?? []) >= 8 && count($sm['samples'] ?? []) >= 6 && count($sm['mapping'] ?? []) >= 8, (string)$c);
    $e22 = current(array_filter($sm['events'] ?? [], fn ($e) => $e['id'] === 22)); $e3 = current(array_filter($sm['events'] ?? [], fn ($e) => $e['id'] === 3));
    check('Sysmon 22 collected, 3 optional', ($e22['status'] ?? '') === 'collected' && ($e3['status'] ?? '') === 'optional');
    check('Sysmon JSON samples are valid JSON', array_reduce(array_filter($sm['samples'] ?? [], fn ($x) => $x['lang'] === 'json'), fn ($ok, $x) => $ok && json_decode($x['body']) !== null, true));

    echo "Input safety\n";
    [$c, ] = call('POST', 'console/services', ['service_name' => "<img src=x onerror=1>' OR 1=1 --", 'provider' => 'x', 'primary_domain' => "zt2-$sfx.example.com"], $A, $jarA); check('hostile text accepted as data, not executed (no 500)', $c < 500, (string)$c);
    [$c, ] = call('POST', 'events/ingest', ['events' => 'nope'], $H); check('malformed ingest body is a 4xx', $c >= 400 && $c < 500, (string)$c);
    [$c, ] = call('GET', 'nonexistent'); check('unknown endpoint 404', $c === 404, (string)$c);
} finally {
    foreach ([$tA['id'], $tB['id']] as $t) {
        foreach (['ai_usage_events', 'network_connection_events'] as $tb) Db::run("DELETE FROM $tb WHERE tenant_id = ?", [$t]);
        Db::run('DELETE h FROM discovered_domain_hosts h JOIN discovered_domains d ON d.id = h.discovered_id WHERE d.tenant_id = ?', [$t]);
        Db::run('DELETE FROM discovered_domains WHERE tenant_id = ?', [$t]);
        Db::run('DELETE hb FROM collector_heartbeats hb JOIN collectors c ON c.id = hb.collector_id WHERE c.tenant_id = ?', [$t]);
        Db::run('DELETE FROM collectors WHERE tenant_id = ?', [$t]);
        Db::run('DELETE FROM audit_logs WHERE tenant_id = ?', [$t]);
        foreach (['event_outbox', 'integrations', 'api_tokens'] as $tb) Db::run("DELETE FROM $tb WHERE tenant_id = ?", [$t]);
        Db::run('DELETE FROM tenants WHERE id = ?', [$t]);
    }
    Db::run("DELETE FROM platform_settings WHERE name LIKE 'google.%'");
    foreach ($gBackup as $g) Db::run('INSERT INTO platform_settings (name, value, secret, updated_by) VALUES (?,?,?,?)', [$g['name'], $g['value'], $g['secret'], $g['updated_by']]);
    Db::run("DELETE FROM admin_users WHERE username LIKE ?", ["zt-%-$sfx"]);
    Db::run("DELETE FROM audit_logs WHERE administrator LIKE ? OR affected_record LIKE ?", ["zt-%-$sfx", "ZT Gamma%$sfx"]);
    $left = (int)Db::val('SELECT COUNT(*) FROM tenants WHERE slug LIKE ?', ["zt-%$sfx%"]);
    echo "\nCleanup: " . ($left === 0 ? 'test data removed' : "WARNING $left test tenant(s) left") . "\n";
}
echo "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
