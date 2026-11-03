<?php
declare(strict_types=1);

namespace Saip\Middleware;

use Psr\Http\Message\{ResponseInterface as Response, ServerRequestInterface as Request};
use Psr\Http\Server\{MiddlewareInterface, RequestHandlerInterface as Handler};
use Saip\{ApiException, Config, Db, RateLimiter, Validator};

/** Machine endpoints: X-Collector-Id + X-Api-Key (keys stored only as SHA-256). Hostnames and MACs are never used for authentication. */
final class CollectorAuth implements MiddlewareInterface
{
    public static function newApiKey(): string { return bin2hex(random_bytes(32)); }
    public static function hashKey(string $key): string { return hash('sha256', $key); }

    public function process(Request $req, Handler $next): Response
    {
        $ip = (string)$req->getAttribute('client_ip');
        $uuid = Validator::uuid($req->getHeaderLine('X-Collector-Id') ?: null);
        $key = $req->getHeaderLine('X-Api-Key') ?: null;
        $fail = static function () use ($ip): never {
            RateLimiter::hit('authfail:' . $ip, (int)Config::get('limits.rate_auth_fail_ip', 30));
            throw new ApiException(401, 'unauthorized', 'Invalid collector credentials.');
        };
        if ($uuid === null || $key === null || strlen($key) > 128) $fail();
        $c = Db::one('SELECT * FROM collectors WHERE collector_uuid = ?', [$uuid]);
        if (!$c || !hash_equals($c['api_key_hash'], self::hashKey($key))) $fail();
        if (in_array($c['status'], ['suspended', 'revoked'], true)) throw new ApiException(403, 'collector_' . $c['status'], 'This collector is ' . $c['status'] . '.');
        if ($c['status'] !== 'authorized') throw new ApiException(403, 'collector_pending', 'Collector is awaiting administrator authorization.');
        RateLimiter::hit('collector:' . $c['id'], (int)Config::get('limits.rate_collector', 120));
        Db::run('UPDATE collectors SET last_seen = UTC_TIMESTAMP() WHERE id = ?', [$c['id']]);
        return $next->handle($req->withAttribute('collector', $c));
    }
}
