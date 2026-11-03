<?php
declare(strict_types=1);

namespace Saip\Modules;

use Psr\Http\Message\{ResponseInterface as Response, ServerRequestInterface as Request};
use Saip\{ApiException, Audit, Db, EventBus, HttpClient, IntegrationDispatcher, Validator};
use Saip\Http\Controller;
use Saip\Middleware\RequirePermission as Need;
use Saip\Security\Secrets;
use Slim\Routing\RouteCollectorProxy as Group;

/**
 * SIEM and webhook integrations (per company) and SIEM pull tokens.
 *  - webhook: HTTPS POST, JSON (HMAC-SHA256 signed) or CEF
 *  - splunk_hec: Splunk HTTP Event Collector
 *  - syslog: UDP/TCP, RFC 5424 with CEF or JSON (QRadar, ArcSight, Sentinel/Elastic via syslog forwarders)
 *  - API tokens: let a SIEM poll GET /api/v1/siem/events and /siem/usage
 */
final class IntegrationsModule extends Controller
{
    public static function register(Group $g): void
    {
        $g->get('/integrations', [self::class, 'list'])->add(new Need('integrations.read'));
        $g->post('/integrations', [self::class, 'create'])->add(new Need('integrations.write'));
        $g->post('/integrations/delete', [self::class, 'delete'])->add(new Need('integrations.delete'));
        $g->post('/integrations/{id:\d+}', [self::class, 'update'])->add(new Need('integrations.write'));
        $g->post('/integrations/{id:\d+}/test', [self::class, 'test'])->add(new Need('integrations.write'));
        $g->post('/integrations/{id:\d+}/run', [self::class, 'run'])->add(new Need('integrations.write'));
        $g->get('/integrations/{id:\d+}/deliveries', [self::class, 'deliveries'])->add(new Need('integrations.read'));
        $g->post('/integration-tokens', [self::class, 'tokenCreate'])->add(new Need('integrations.write'));
        $g->post('/integration-tokens/delete', [self::class, 'tokenDelete'])->add(new Need('integrations.delete'));
    }

    private function mask(array $r): array
    {
        $r['has_secret'] = $r['secret_enc'] !== null && $r['secret_enc'] !== '';
        unset($r['secret_enc']);
        $r['events'] = array_values(array_filter(explode(',', (string)$r['events'])));
        return $r;
    }

    public function list(Request $req, Response $res): Response
    {
        $t = $this->tid($req);
        return $this->json($res, [
            'integrations' => array_map(fn ($r) => $this->mask($r), Db::all('SELECT * FROM integrations WHERE tenant_id = ? ORDER BY name', [$t])),
            'tokens' => Db::all('SELECT id, name, scope, last_used_at, created_by, created_at FROM api_tokens WHERE tenant_id = ? AND revoked = 0 ORDER BY id DESC', [$t]),
            'event_types' => EventBus::TYPES,
            'pull' => ['events' => '/api/v1/siem/events', 'usage' => '/api/v1/siem/usage'],
        ]);
    }

    /** Validates and normalises the body shared by create and update. @return array<string,mixed> */
    private function fields(array $b, ?array $cur): array
    {
        $kind = (string)($b['kind'] ?? $cur['kind'] ?? '');
        if (!in_array($kind, ['webhook', 'splunk_hec', 'syslog'], true)) throw new ApiException(422, 'validation_failed', 'Choose a type: webhook, splunk_hec or syslog.', ['kind' => 'invalid']);
        $f = ['kind' => $kind, 'name' => $this->str($b, 'name', 100, true)];
        $f['format'] = in_array($b['format'] ?? $cur['format'] ?? 'json', ['json', 'cef'], true) ? ($b['format'] ?? $cur['format'] ?? 'json') : 'json';
        if ($kind === 'splunk_hec') $f['format'] = 'json';
        $events = $b['events'] ?? ($cur ? explode(',', (string)$cur['events']) : array_keys(array_diff_key(EventBus::TYPES, ['usage.event' => 1])));
        if (!is_array($events)) $events = explode(',', (string)$events);
        $events = array_values(array_unique(array_filter(array_map('trim', $events))));
        foreach ($events as $e) if (!isset(EventBus::TYPES[$e])) throw new ApiException(422, 'validation_failed', "Unknown event type: $e", ['events' => 'invalid']);
        if (!$events) throw new ApiException(422, 'validation_failed', 'Select at least one event type.', ['events' => 'required']);
        $f['events'] = implode(',', $events);
        $f['active'] = array_key_exists('active', $b) ? ($b['active'] ? 1 : 0) : (int)($cur['active'] ?? 1);
        if ($kind === 'syslog') {
            $host = trim((string)($b['host'] ?? $cur['host'] ?? ''));
            if (!filter_var($host, FILTER_VALIDATE_IP) && Validator::hostname($host) === null) throw new ApiException(422, 'validation_failed', 'A valid host name or IP is required.', ['host' => 'invalid']);
            $port = (int)($b['port'] ?? $cur['port'] ?? 514);
            if ($port < 1 || $port > 65535) throw new ApiException(422, 'validation_failed', 'Port must be 1-65535.', ['port' => 'invalid']);
            $proto = ($b['protocol'] ?? $cur['protocol'] ?? 'udp') === 'tcp' ? 'tcp' : 'udp';
            $f += ['host' => strtolower($host), 'port' => $port, 'protocol' => $proto, 'url' => null];
        } else {
            $url = trim((string)($b['url'] ?? $cur['url'] ?? ''));
            HttpClient::assertPublic($url);
            if (mb_strlen($url) > 500) throw new ApiException(422, 'validation_failed', 'URL is too long.', ['url' => 'invalid']);
            $f += ['url' => $url, 'host' => null, 'port' => null, 'protocol' => null];
        }
        return $f;
    }

    public function create(Request $req, Response $res): Response
    {
        $t = $this->tid($req); $b = $this->body($req);
        $f = $this->fields($b, null);
        if (Db::val('SELECT 1 FROM integrations WHERE tenant_id = ? AND name = ?', [$t, $f['name']])) throw new ApiException(409, 'duplicate', 'An integration with this name already exists.');
        $secret = trim((string)($b['secret'] ?? ''));
        $shown = null;
        if ($f['kind'] === 'splunk_hec' && $secret === '') throw new ApiException(422, 'validation_failed', 'The Splunk HEC token is required.', ['secret' => 'required']);
        if ($f['kind'] === 'webhook' && $secret === '') { $secret = 'whsec_' . bin2hex(random_bytes(24)); $shown = $secret; }   // generated signing secret, shown once
        $enc = $secret !== '' ? Secrets::encrypt($secret) : null;
        // start from now: do not replay history into a new integration
        $co = (int)Db::val('SELECT COALESCE(MAX(id), 0) FROM event_outbox WHERE tenant_id = ?', [$t]); $cu = (int)Db::val('SELECT COALESCE(MAX(id), 0) FROM ai_usage_events WHERE tenant_id = ?', [$t]);
        Db::run('INSERT INTO integrations (tenant_id, name, kind, url, host, port, protocol, format, secret_enc, events, active, cursor_outbox, cursor_usage, created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
            [$t, $f['name'], $f['kind'], $f['url'], $f['host'], $f['port'], $f['protocol'], $f['format'], $enc, $f['events'], $f['active'], $co, $cu, $this->actor($req)]);
        $id = Db::insertId();
        EventBus::reset();
        Audit::log($this->actor($req), 'integration_created', $f['name'], null, $t, null, ['kind' => $f['kind'], 'events' => $f['events'], 'url' => $f['url'], 'host' => $f['host']]);
        return $this->json($res, ['id' => $id, 'signing_secret' => $shown], 201);
    }

    public function update(Request $req, Response $res, array $a): Response
    {
        $t = $this->tid($req); $b = $this->body($req);
        $cur = Db::one('SELECT * FROM integrations WHERE id = ? AND tenant_id = ?', [(int)$a['id'], $t]);
        if (!$cur) throw new ApiException(404, 'not_found', 'Unknown integration.');
        $b += ['name' => $cur['name']];
        $f = $this->fields($b, $cur);
        if ($f['name'] !== $cur['name'] && Db::val('SELECT 1 FROM integrations WHERE tenant_id = ? AND name = ? AND id <> ?', [$t, $f['name'], $cur['id']])) throw new ApiException(409, 'duplicate', 'An integration with this name already exists.');
        $set = $f;
        $secret = trim((string)($b['secret'] ?? ''));
        if ($secret !== '') $set['secret_enc'] = Secrets::encrypt($secret);
        $shown = null;
        if (!empty($b['rotate_secret']) && $cur['kind'] === 'webhook') { $shown = 'whsec_' . bin2hex(random_bytes(24)); $set['secret_enc'] = Secrets::encrypt($shown); }
        if (!empty($b['reset_failures'])) { $set['failures'] = 0; $set['next_attempt_at'] = null; $set['last_status'] = null; $set['last_error'] = null; }
        $set['updated_at'] = gmdate('Y-m-d H:i:s');
        Db::run('UPDATE integrations SET ' . implode(', ', array_map(static fn ($k) => "`$k` = ?", array_keys($set))) . ' WHERE id = ?', array_merge(array_values($set), [$cur['id']]));
        EventBus::reset();
        Audit::log($this->actor($req), 'integration_updated', $f['name'], ['secret_rotated' => $shown !== null || $secret !== ''], $t, array_intersect_key($cur, $f), $f);
        return $this->json($res, ['status' => 'ok', 'signing_secret' => $shown]);
    }

    public function delete(Request $req, Response $res): Response
    {
        $t = $this->tid($req); $b = $this->body($req); $ids = $this->ids($b);
        $rows = Db::all('SELECT id, name FROM integrations WHERE tenant_id = ? AND id IN (' . $this->in($ids) . ')', array_merge([$t], $ids));
        if (!$rows) throw new ApiException(404, 'not_found', 'No matching integrations.');
        $impact = ['records' => count($rows), 'names' => array_column($rows, 'name')];
        if (!empty($b['preview'])) return $this->json($res, ['preview' => $impact]);
        $rid = array_map(static fn ($r) => (int)$r['id'], $rows);
        Db::run('DELETE FROM integrations WHERE tenant_id = ? AND id IN (' . $this->in($rid) . ')', array_merge([$t], $rid));   // deliveries cascade
        EventBus::reset();
        Audit::log($this->actor($req), 'integration_deleted', implode(', ', array_slice($impact['names'], 0, 5)), $impact, $t, $impact, null);
        return $this->json($res, ['deleted' => $impact]);
    }

    public function test(Request $req, Response $res, array $a): Response
    {
        $t = $this->tid($req);
        $i = Db::one('SELECT * FROM integrations WHERE id = ? AND tenant_id = ?', [(int)$a['id'], $t]);
        if (!$i) throw new ApiException(404, 'not_found', 'Unknown integration.');
        $r = IntegrationDispatcher::test($i);
        Audit::log($this->actor($req), 'integration_tested', $i['name'], ['ok' => $r['ok'], 'http' => $r['http']], $t);
        return $this->json($res, $r);
    }

    /** Delivers pending events now (otherwise the scheduled worker does it). */
    public function run(Request $req, Response $res, array $a): Response
    {
        $t = $this->tid($req);
        if (!Db::val('SELECT 1 FROM integrations WHERE id = ? AND tenant_id = ?', [(int)$a['id'], $t])) throw new ApiException(404, 'not_found', 'Unknown integration.');
        return $this->json($res, ['results' => IntegrationDispatcher::run((int)$a['id'], true)]);
    }

    public function deliveries(Request $req, Response $res, array $a): Response
    {
        $t = $this->tid($req);
        if (!Db::val('SELECT 1 FROM integrations WHERE id = ? AND tenant_id = ?', [(int)$a['id'], $t])) throw new ApiException(404, 'not_found', 'Unknown integration.');
        return $this->json($res, ['deliveries' => Db::all('SELECT id, event_count, status, http_status, error, duration_ms, created_at FROM integration_deliveries WHERE integration_id = ? ORDER BY id DESC LIMIT 200', [(int)$a['id']])]);
    }

    public function tokenCreate(Request $req, Response $res): Response
    {
        $t = $this->tid($req); $b = $this->body($req);
        $name = $this->str($b, 'name', 100, true);
        $token = 'saip_siem_' . bin2hex(random_bytes(24));
        Db::run('INSERT INTO api_tokens (tenant_id, name, token_hash, created_by) VALUES (?,?,?,?)', [$t, $name, hash('sha256', $token), $this->actor($req)]);
        $id = Db::insertId();
        EventBus::reset();
        Audit::log($this->actor($req), 'api_token_created', $name, null, $t);
        return $this->json($res, ['id' => $id, 'token' => $token, 'note' => 'Shown once. Send it as "Authorization: Bearer <token>".'], 201);
    }

    public function tokenDelete(Request $req, Response $res): Response
    {
        $t = $this->tid($req); $b = $this->body($req); $ids = $this->ids($b);
        $rows = Db::all('SELECT id, name FROM api_tokens WHERE tenant_id = ? AND id IN (' . $this->in($ids) . ')', array_merge([$t], $ids));
        if (!$rows) throw new ApiException(404, 'not_found', 'No matching tokens.');
        $rid = array_map(static fn ($r) => (int)$r['id'], $rows);
        Db::run('DELETE FROM api_tokens WHERE tenant_id = ? AND id IN (' . $this->in($rid) . ')', array_merge([$t], $rid));
        EventBus::reset();
        Audit::log($this->actor($req), 'api_token_revoked', implode(', ', array_column($rows, 'name')), null, $t);
        return $this->json($res, ['deleted' => ['records' => count($rows), 'names' => array_column($rows, 'name')]]);
    }
}
