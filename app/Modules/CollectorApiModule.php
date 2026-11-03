<?php
declare(strict_types=1);

namespace Saip\Modules;

use Psr\Http\Message\{ResponseInterface as Response, ServerRequestInterface as Request};
use Saip\{ApiException, Audit, Config, Db, DomainRegistry, EventBus, IpIntel, RateLimiter, Validator};
use Saip\Http\Controller;
use Saip\Middleware\CollectorAuth;
use Slim\Routing\RouteCollectorProxy as Group;

/** Machine API used by workstation collectors: register, heartbeat, config, ingest. No browser session; per-collector keys. */
final class CollectorApiModule extends Controller
{
    public static function register(Group $g): void
    {
        $g->post('/collector/register', [self::class, 'enroll']);
        $auth = new CollectorAuth();
        $g->post('/collector/heartbeat', [self::class, 'heartbeat'])->add($auth);
        $g->get('/collector/domains', [self::class, 'domains'])->add($auth);   // legacy v1.0.0 collectors
        $g->get('/collector/config', [self::class, 'config'])->add($auth);
        $g->post('/events/ingest', [self::class, 'ingest'])->add($auth);
    }

    /** The enrollment key identifies the company (tenant). */
    public function enroll(Request $req, Response $res): Response
    {
        $ip = (string)$req->getAttribute('client_ip');
        RateLimiter::hit('register:' . $ip, (int)Config::get('limits.rate_register_ip', 10));
        $given = $req->getHeaderLine('X-Enrollment-Key');
        $tenant = $given === '' ? null : Db::one("SELECT id, name FROM tenants WHERE enrollment_key_hash = ? AND status = 'active'", [hash('sha256', $given)]);
        if (!$tenant) {
            RateLimiter::hit('authfail:' . $ip, (int)Config::get('limits.rate_auth_fail_ip', 30));
            throw new ApiException(401, 'unauthorized', 'Invalid enrollment key.');
        }
        $b = $this->body($req);
        $name = Validator::computerName($b['computer_name'] ?? null);
        $uuid = Validator::uuid($b['collector_uuid'] ?? null);
        $mac = isset($b['mac_address']) && $b['mac_address'] !== '' ? Validator::mac($b['mac_address']) : null;
        $ver = Validator::version($b['collector_version'] ?? '1.0.0');
        $errors = [];
        if ($name === null) $errors['computer_name'] = 'invalid';
        if ($uuid === null) $errors['collector_uuid'] = 'invalid';
        if (isset($b['mac_address']) && $b['mac_address'] !== '' && $mac === null) $errors['mac_address'] = 'invalid';
        if ($ver === null) $errors['collector_version'] = 'invalid';
        if ($errors) throw new ApiException(422, 'validation_failed', 'Invalid registration data.', $errors);
        if (Db::val('SELECT id FROM collectors WHERE collector_uuid = ?', [$uuid])) {
            throw new ApiException(409, 'already_registered', 'This collector is already registered. Ask an administrator to rotate its credential.');
        }
        $key = CollectorAuth::newApiKey();
        $status = Config::get('auto_authorize', false) ? 'authorized' : 'pending';
        Db::run('INSERT INTO collectors (tenant_id, computer_name, mac_address, collector_uuid, api_key_hash, status, collector_version, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP())',
            [$tenant['id'], $name, $mac, $uuid, CollectorAuth::hashKey($key), $status, $ver]);
        Audit::log('system:register', 'collector_registered', $uuid, ['computer_name' => $name, 'status' => $status], (int)$tenant['id']);
        return $this->json($res, [
            'status' => $status, 'company' => $tenant['name'], 'collector_uuid' => $uuid,
            'api_key' => $key,   // shown ONCE; only its hash is stored
            'message' => $status === 'pending' ? 'Registered. Awaiting administrator authorization.' : 'Registered and authorized.',
        ], 201);
    }

    public function heartbeat(Request $req, Response $res): Response
    {
        $c = $req->getAttribute('collector'); $b = $this->body($req);
        $ver = Validator::version($b['collector_version'] ?? null) ?? $c['collector_version'];
        $status = in_array($b['status'] ?? 'ok', ['ok', 'degraded', 'error'], true) ? ($b['status'] ?? 'ok') : 'ok';
        $int = static fn (string $k) => isset($b[$k]) && is_int($b[$k]) && $b[$k] >= 0 ? $b[$k] : null;
        $cfg = $int('config_version'); $spool = $int('spool_depth'); $failed = $int('failed_submissions');
        $err = isset($b['last_error']) && is_string($b['last_error']) && $b['last_error'] !== '' ? mb_substr($b['last_error'], 0, 300) : null;
        $ip = isset($b['workstation_ip']) && is_string($b['workstation_ip']) && filter_var($b['workstation_ip'], FILTER_VALIDATE_IP) ? $b['workstation_ip'] : null;
        Db::run('INSERT INTO collector_heartbeats (collector_id, collector_version, status, config_version, spool_depth, failed_submissions, last_error) VALUES (?,?,?,?,?,?,?)',
            [$c['id'], $ver, $status, $cfg, $spool, $failed, $err]);
        Db::run('UPDATE collectors SET collector_version = ?, last_seen = UTC_TIMESTAMP(), config_version_applied = COALESCE(?, config_version_applied),
                 spool_depth = COALESCE(?, spool_depth), failed_submissions = COALESCE(?, failed_submissions), last_error = ?, workstation_ip = COALESCE(?, workstation_ip) WHERE id = ?',
            [$ver, $cfg, $spool, $failed, $err, $ip, $c['id']]);
        return $this->json($res, ['status' => 'ok', 'server_time_utc' => gmdate('Y-m-d\TH:i:s\Z'), 'config_version' => DomainRegistry::version((int)$c['tenant_id'])]);
    }

    /** Central registry rules + monitoring options; collectors cache this and re-sync when the version changes. */
    public function config(Request $req, Response $res): Response
    {
        $c = $req->getAttribute('collector'); $t = (int)$c['tenant_id'];
        $version = DomainRegistry::version($t);
        $s = $this->q($req, 'since');
        $since = $s !== null && ctype_digit((string)$s) ? (int)$s : null;
        Db::run('UPDATE collectors SET last_config_sync = UTC_TIMESTAMP(), config_version_applied = ? WHERE id = ?', [$version, $c['id']]);
        if ($since !== null && $since === $version) return $this->json($res, ['config_version' => $version, 'unchanged' => true]);
        $rules = Db::all('SELECT d.domain, d.matching_rule, d.domain_type, s.id service_id, s.service_name service, s.sanction_status classification
             FROM ai_domains d JOIN ai_services s ON s.id = d.ai_service_id
             WHERE d.tenant_id = ? AND d.active = 1 AND s.active = 1 AND s.archived = 0 ORDER BY d.domain', [$t]);
        foreach ($rules as &$r) $r['service_id'] = (int)$r['service_id'];
        $mon = DomainRegistry::monitoring($t);
        $out = ['config_version' => $version, 'rules' => $rules, 'monitoring' => $mon];
        if ($mon['network_events']) $out['ip_rules'] = IpIntel::rules($t);   // dedicated addresses only; lets the collector keep EID 3 events that have no host name
        return $this->json($res, $out);
    }

    public function domains(Request $req, Response $res): Response
    {
        $c = $req->getAttribute('collector');
        return $this->json($res, ['domains' => Db::all('SELECT d.domain, s.service_name AS service FROM ai_domains d JOIN ai_services s ON s.id = d.ai_service_id
             WHERE d.tenant_id = ? AND d.active = 1 AND s.active = 1 AND s.archived = 0 AND s.sanction_status <> "excluded" ORDER BY d.domain', [$c['tenant_id']])]);
    }

    public function ingest(Request $req, Response $res): Response
    {
        $c = $req->getAttribute('collector'); $b = $this->body($req);
        $events = $b['events'] ?? null;
        $max = (int)Config::get('limits.max_events_per_call', 500);
        if (!is_array($events) || !array_is_list($events) || $events === []) throw new ApiException(422, 'validation_failed', '"events" must be a non-empty array.');
        if (count($events) > $max) throw new ApiException(413, 'too_many_events', "At most $max events per request.");

        $pdo = Db::pdo(); $tenantId = (int)$c['tenant_id'];
        $map = DomainRegistry::load($tenantId);
        $wsIp = isset($b['workstation_ip']) && is_string($b['workstation_ip']) && filter_var($b['workstation_ip'], FILTER_VALIDATE_IP) ? $b['workstation_ip'] : null;

        $insert = $pdo->prepare('INSERT IGNORE INTO ai_usage_events (tenant_id, collector_id, computer_name, ai_service_id, query_domain, process_image, process_id,
              sysmon_record_id, event_timestamp, received_timestamp, event_type, query_status, process_guid, workstation_ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP(3), ?, ?, ?, ?)');
        $net = $pdo->prepare('INSERT IGNORE INTO network_connection_events (tenant_id, collector_id, computer_name, ai_service_id, destination_host, destination_ip, destination_port, protocol,
              process_image, process_guid, sysmon_record_id, event_timestamp, match_basis) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)');
        $disc = $pdo->prepare('INSERT INTO discovered_domains (tenant_id, domain, hit_count, first_seen, last_seen) VALUES (?, ?, 1, ?, ?)
             ON DUPLICATE KEY UPDATE id = LAST_INSERT_ID(id), hit_count = hit_count + 1, first_seen = LEAST(first_seen, VALUES(first_seen)), last_seen = GREATEST(last_seen, VALUES(last_seen))');
        $discHost = $pdo->prepare('INSERT INTO discovered_domain_hosts (discovered_id, computer_name, hit_count, first_seen, last_seen) VALUES (?, ?, 1, ?, ?)
             ON DUPLICATE KEY UPDATE hit_count = hit_count + 1, first_seen = LEAST(first_seen, VALUES(first_seen)), last_seen = GREATEST(last_seen, VALUES(last_seen))');
        $seen = $pdo->prepare('UPDATE ai_domains SET first_observed = COALESCE(LEAST(first_observed, ?), ?), last_observed = GREATEST(COALESCE(last_observed, ?), ?) WHERE tenant_id = ? AND domain = ?');

        $accepted = $duplicates = $unmatched = $excluded = $ambiguous = 0; $rejected = []; $alerts = []; $svcInfo = []; $pairSeen = [];
        $watch = EventBus::active($tenantId);
        $pdo->beginTransaction();
        try {
            foreach ($events as $i => $e) {
                if (!is_array($e)) { $rejected[] = ['index' => $i, 'reason' => 'not an object']; continue; }
                $type = $e['event_type'] ?? 'dns_query';
                $isNet = $type === 'network_connection';
                $domain = Validator::hostname($isNet ? ($e['destination_host'] ?? null) : ($e['query_domain'] ?? null));
                $ts = Validator::utcTimestamp($e['event_timestamp'] ?? null);
                $rid = $e['sysmon_record_id'] ?? null; $pid = $e['process_id'] ?? null; $img = $e['process_image'] ?? null;
                $guid = $e['process_guid'] ?? null; $status = $e['query_status'] ?? null; $dip = $e['destination_ip'] ?? null; $dport = $e['destination_port'] ?? null;

                $why = null;
                if (!in_array($type, ['dns_query', 'network_connection'], true)) $why = 'invalid event_type';
                elseif (!$isNet && $domain === null) $why = 'invalid query_domain';
                elseif ($isNet && ($dip === null || !is_string($dip) || !filter_var($dip, FILTER_VALIDATE_IP))) $why = 'invalid destination_ip';
                elseif ($isNet && $dport !== null && (!is_int($dport) || $dport < 0 || $dport > 65535)) $why = 'invalid destination_port';
                elseif ($ts === null) $why = 'invalid event_timestamp';
                elseif (!is_int($rid) || $rid < 1) $why = 'invalid sysmon_record_id';
                elseif ($pid !== null && (!is_int($pid) || $pid < 0)) $why = 'invalid process_id';
                elseif ($img !== null && !is_string($img)) $why = 'invalid process_image';
                elseif ($guid !== null && (!is_string($guid) || !preg_match('/^\{?[0-9a-fA-F-]{36}\}?$/', $guid))) $why = 'invalid process_guid';
                elseif ($status !== null && (!is_string($status) || !preg_match('/^[A-Za-z0-9_ ()-]{1,40}$/', $status))) $why = 'invalid query_status';
                if ($why !== null) { $rejected[] = ['index' => $i, 'reason' => $why]; continue; }
                $guid = $guid === null ? null : trim($guid, '{}');
                $img = $img === null ? null : mb_substr($img, 0, 512);

                $m = $domain === null ? null : DomainRegistry::match($domain, $map);
                if ($m !== null && $m[1]) { $excluded++; continue; }          // registry says this is a known non-AI domain
                if ($isNet) {
                    $basis = 'host';
                    if ($m === null) {                                       // no usable host name: try the address, which only counts when it is dedicated to one service
                        $hit = IpIntel::lookup($tenantId, $dip);
                        if ($hit === null) { $unmatched++; continue; }
                        if ($hit['shared']) { $ambiguous++; continue; }        // CDN / shared address: cannot show which site was visited
                        $m = [$hit['service_id'], false]; $basis = 'ip';
                    }
                    $net->execute([$tenantId, $c['id'], $c['computer_name'], $m[0], $domain, $dip, $dport, isset($e['protocol']) && is_string($e['protocol']) ? mb_substr($e['protocol'], 0, 10) : null, $img, $guid, $rid, $ts, $basis]);
                    $net->rowCount() === 1 ? $accepted++ : $duplicates++;
                    continue;
                }
                if ($m === null) {
                    // Not in the registry: keep for the discovery workflow, never as usage.
                    $known = Db::val('SELECT status FROM discovered_domains WHERE tenant_id = ? AND domain = ?', [$tenantId, $domain]);
                    if ($known !== 'excluded') {
                        $disc->execute([$tenantId, $domain, $ts, $ts]);
                        if ($watch && $disc->rowCount() === 1) $alerts[] = ['discovery.new_domain', ['domain' => $domain, 'computer' => $c['computer_name'], 'first_seen' => $ts]];
                        $discHost->execute([(int)$pdo->lastInsertId(), $c['computer_name'], $ts, $ts]);
                    }
                    $unmatched++;
                    continue;
                }
                // computer_name comes from the authenticated collector record, not the payload.
                if ($watch) {   // first time this unsanctioned service is seen on this computer?
                    $svcInfo[$m[0]] ??= Db::one('SELECT service_name, sanction_status FROM ai_services WHERE id = ?', [$m[0]]);
                    $pk = $m[0] . '|' . $c['computer_name'];
                    $pairSeen[$pk] ??= (bool)Db::val('SELECT 1 FROM ai_usage_events WHERE tenant_id = ? AND ai_service_id = ? AND computer_name = ? LIMIT 1', [$tenantId, $m[0], $c['computer_name']]);
                    if (!$pairSeen[$pk] && ($svcInfo[$m[0]]['sanction_status'] ?? 'sanctioned') !== 'sanctioned') {
                        $alerts[] = ['shadow_ai.detected', ['service' => $svcInfo[$m[0]]['service_name'], 'classification' => $svcInfo[$m[0]]['sanction_status'], 'computer' => $c['computer_name'], 'host' => $domain, 'process' => $img, 'time' => $ts]];
                        $pairSeen[$pk] = true;
                    }
                }
                $insert->execute([$tenantId, $c['id'], $c['computer_name'], $m[0], $domain, $img, $pid, $rid, $ts, $type, $status, $guid, $wsIp]);
                if ($insert->rowCount() === 1) { $accepted++; $seen->execute([$ts, $ts, $ts, $ts, $tenantId, $domain]); } else { $duplicates++; }
            }
            $pdo->commit();
        } catch (\Throwable $t) { $pdo->rollBack(); throw $t; }
        foreach ($alerts as [$type, $data]) EventBus::emit($tenantId, $type, $data);
        if ($rejected) Audit::log('system:ingest', 'ingest_rejected_events', $c['collector_uuid'], ['count' => count($rejected)], $tenantId);
        return $this->json($res, ['status' => 'ok', 'received' => count($events), 'accepted' => $accepted, 'duplicates' => $duplicates, 'unmatched' => $unmatched,
            'ambiguous' => $ambiguous, 'excluded' => $excluded, 'rejected' => array_slice($rejected, 0, 50), 'config_version' => DomainRegistry::version($tenantId)]);
    }
}
