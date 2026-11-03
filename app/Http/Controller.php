<?php
declare(strict_types=1);

namespace Saip\Http;

use Psr\Http\Message\{ResponseInterface as Response, ServerRequestInterface as Request};
use Saip\{ApiException, Config};
use Saip\Security\Auth;

/** Shared helpers for module controllers. Handlers are `method(Request, Response, array $args): Response`. */
abstract class Controller
{
    /** Request id of the current request (set by RequestContext). */
    public static string $requestId = '';

    protected function json(Response $res, array $data, int $status = 200): Response
    {
        $data['request_id'] = self::$requestId;
        $res->getBody()->write(json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE));
        return $res->withStatus($status)->withHeader('Content-Type', 'application/json; charset=utf-8');
    }

    protected function raw(Response $res, string $body, string $type, ?string $filename = null): Response
    {
        $res->getBody()->write($body);
        $res = $res->withHeader('Content-Type', $type);
        return $filename === null ? $res : $res->withHeader('Content-Disposition', 'attachment; filename="' . preg_replace('/[^A-Za-z0-9._-]/', '_', $filename) . '"');
    }

    /** CSV with spreadsheet-formula injection neutralised (OWASP CSV Injection). */
    protected function csv(array $header, array $rows): string
    {
        $f = fopen('php://temp', 'r+');
        fputcsv($f, $header, ',', '"', '\\');
        foreach ($rows as $r) {
            fputcsv($f, array_map(static fn ($c) => is_string($c) && preg_match('/^[=+\-@\t\r]/', $c) ? "'" . $c : $c, $r), ',', '"', '\\');
        }
        rewind($f);
        return "\xEF\xBB\xBF" . stream_get_contents($f);
    }

    /** Decodes a JSON object body, enforcing size and content type. */
    protected function body(Request $req): array
    {
        $max = (int)Config::get('limits.max_body_bytes', 1048576);
        if ((int)$req->getHeaderLine('Content-Length') > $max) throw new ApiException(413, 'payload_too_large', "Request body exceeds $max bytes.");
        if (!str_starts_with(strtolower($req->getHeaderLine('Content-Type')), 'application/json')) throw new ApiException(415, 'unsupported_media_type', 'Content-Type must be application/json.');
        $raw = (string)$req->getBody();
        if (strlen($raw) > $max) throw new ApiException(413, 'payload_too_large', "Request body exceeds $max bytes.");
        try {
            $data = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw new ApiException(400, 'invalid_json', 'Request body is not valid JSON.');
        }
        if (!is_array($data) || (array_is_list($data) && $data !== [])) throw new ApiException(400, 'invalid_json', 'JSON body must be an object.');
        return $data;
    }

    protected function user(Request $r): array { return $r->getAttribute('user'); }
    protected function actor(Request $r): string { return $r->getAttribute('user')['username']; }
    protected function tid(Request $r): int { return Auth::tenantId($r->getAttribute('user')); }
    protected function q(Request $r, string $k, mixed $d = null): mixed { return $r->getQueryParams()[$k] ?? $d; }

    protected function str(array $b, string $k, int $max, bool $required = false): ?string
    {
        $v = $b[$k] ?? null;
        if ($v === null || $v === '') {
            if ($required) throw new ApiException(422, 'validation_failed', "$k is required.", [$k => 'required']);
            return null;
        }
        if (!is_string($v) || mb_strlen(trim($v)) > $max) throw new ApiException(422, 'validation_failed', "$k is invalid or too long.", [$k => 'invalid']);
        return trim($v);
    }

    protected function pct(array $b, string $k): ?int
    {
        if (!array_key_exists($k, $b)) return null;
        if (!is_numeric($b[$k]) || $b[$k] < 0 || $b[$k] > 100) throw new ApiException(422, 'validation_failed', "$k must be 0-100.", [$k => 'invalid']);
        return (int)$b[$k];
    }

    /** @return list<int> validated, unique ids from {ids:[...]} */
    protected function ids(array $b, int $max = 500): array
    {
        $ids = array_values(array_unique(array_filter(array_map('intval', is_array($b['ids'] ?? null) ? $b['ids'] : []), static fn ($i) => $i > 0)));
        if (!$ids) throw new ApiException(422, 'validation_failed', 'Select at least one record.');
        if (count($ids) > $max) throw new ApiException(422, 'validation_failed', "At most $max records per request.");
        return $ids;
    }

    protected function in(array $ids): string { return implode(',', array_fill(0, count($ids), '?')); }
}
