<?php
declare(strict_types=1);

namespace Saip\Modules;

use Psr\Http\Message\{ResponseInterface as Response, ServerRequestInterface as Request};
use Psr\Http\Server\{MiddlewareInterface, RequestHandlerInterface as Handler};
use Saip\{ApiException, Config, Db, EventBus, IntegrationDispatcher, RateLimiter};
use Saip\Http\Controller;
use Slim\Routing\RouteCollectorProxy as Group;

/** Pull API for SIEMs: GET /api/v1/siem/events (platform + audit events) and /siem/usage (raw usage stream), authenticated with a Bearer token. */
final class SiemModule extends Controller implements MiddlewareInterface
{
    public static function register(Group $g): void
    {
        $g->get('/siem/events', [self::class, 'events'])->add(new self());
        $g->get('/siem/usage', [self::class, 'usage'])->add(new self());
    }

    /** Bearer-token guard (tokens are stored as SHA-256; per-token rate limit). */
    public function process(Request $req, Handler $next): Response
    {
        $h = $req->getHeaderLine('Authorization');
        $tok = preg_match('/^Bearer\s+(saip_siem_[a-f0-9]{48})$/', $h, $m) ? $m[1] : null;
        $row = $tok ? Db::one('SELECT id, tenant_id FROM api_tokens WHERE token_hash = ? AND revoked = 0', [hash('sha256', $tok)]) : null;
        if (!$row) {
            RateLimiter::hit('authfail:' . $req->getAttribute('client_ip'), (int)Config::get('limits.rate_auth_fail_ip', 30));
            throw new ApiException(401, 'unauthorized', 'A valid API token is required.');
        }
        RateLimiter::hit('siem:' . $row['id'], 120);
        Db::run('UPDATE api_tokens SET last_used_at = UTC_TIMESTAMP() WHERE id = ?', [$row['id']]);
        return $next->handle($req->withAttribute('siem_tenant', (int)$row['tenant_id']));
    }

    private function output(Request $req, Response $res, array $events, int $next, bool $more, string $slug): Response
    {
        $fmt = (string)$this->q($req, 'format', 'json');
        if ($fmt === 'cef') return $this->raw($res, implode("\n", array_map(static fn ($e) => IntegrationDispatcher::cef($e, $slug), $events)) . "\n", 'text/plain; charset=utf-8');
        if ($fmt === 'jsonl') return $this->raw($res, implode("\n", array_map(static fn ($e) => json_encode($e + ['tenant' => $slug], JSON_UNESCAPED_SLASHES), $events)) . "\n", 'application/x-ndjson');
        return $this->json($res, ['events' => array_map(static fn ($e) => $e + ['tenant' => $slug], $events), 'next_id' => $next, 'has_more' => $more]);
    }

    public function events(Request $req, Response $res): Response
    {
        $t = (int)$req->getAttribute('siem_tenant');
        $since = max(0, (int)$this->q($req, 'since_id', 0)); $limit = max(1, min(1000, (int)$this->q($req, 'limit', 500)));
        $types = array_values(array_filter(explode(',', (string)$this->q($req, 'types', '')), static fn ($x) => isset(EventBus::TYPES[$x])));
        $w = $types ? ' AND type IN (' . implode(',', array_fill(0, count($types), '?')) . ')' : '';
        $rows = Db::all("SELECT id, type, payload, created_at FROM event_outbox WHERE tenant_id = ? AND id > ? $w ORDER BY id LIMIT " . ($limit + 1), array_merge([$t, $since], $types));
        $more = count($rows) > $limit; $rows = array_slice($rows, 0, $limit);
        $events = array_map(static fn ($r) => ['id' => 'o' . $r['id'], 'type' => $r['type'], 'time' => gmdate('Y-m-d\TH:i:s\Z', strtotime($r['created_at'] . ' UTC')), 'data' => json_decode($r['payload'], true) ?: []], $rows);
        return $this->output($req, $res, $events, $rows ? (int)end($rows)['id'] : $since, $more, (string)Db::val('SELECT slug FROM tenants WHERE id = ?', [$t]));
    }

    public function usage(Request $req, Response $res): Response
    {
        $t = (int)$req->getAttribute('siem_tenant');
        $since = max(0, (int)$this->q($req, 'since_id', 0)); $limit = max(1, min(1000, (int)$this->q($req, 'limit', 500)));
        $rows = Db::all('SELECT e.id, e.computer_name, e.event_timestamp, e.query_domain, e.process_image, e.workstation_ip, s.service_name, s.sanction_status
                         FROM ai_usage_events e JOIN ai_services s ON s.id = e.ai_service_id WHERE e.tenant_id = ? AND e.id > ? ORDER BY e.id LIMIT ' . ($limit + 1), [$t, $since]);
        $more = count($rows) > $limit; $rows = array_slice($rows, 0, $limit);
        $events = array_map(static fn ($r) => ['id' => 'u' . $r['id'], 'type' => 'usage.event', 'time' => gmdate('Y-m-d\TH:i:s\Z', strtotime($r['event_timestamp'] . ' UTC')),
            'data' => ['computer' => $r['computer_name'], 'service' => $r['service_name'], 'classification' => $r['sanction_status'], 'host' => $r['query_domain'], 'process' => $r['process_image'], 'workstation_ip' => $r['workstation_ip']]], $rows);
        return $this->output($req, $res, $events, $rows ? (int)end($rows)['id'] : $since, $more, (string)Db::val('SELECT slug FROM tenants WHERE id = ?', [$t]));
    }
}
