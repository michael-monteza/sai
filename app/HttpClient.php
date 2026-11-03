<?php
declare(strict_types=1);

namespace Saip;

/** Outbound HTTPS with SSRF protection: public destinations only (unless explicitly allowed for lab use), no redirects, short timeouts. */
final class HttpClient
{
    /** @return array{status:int,body:string,error:?string,ms:int} */
    public static function request(string $method, string $url, array $headers = [], ?string $body = null, int $timeout = 10, bool $guard = true): array
    {
        if ($guard) self::assertPublic($url);
        $t0 = microtime(true);
        $ch = curl_init($url);
        $h = [];
        foreach ($headers as $k => $v) $h[] = "$k: $v";
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST => $method, CURLOPT_HTTPHEADER => $h, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => $timeout, CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_FOLLOWLOCATION => false, CURLOPT_MAXREDIRS => 0, CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS, CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT => 'SAIP/1.0',
        ]);
        if ($body !== null) curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        $out = curl_exec($ch);
        $err = $out === false ? curl_error($ch) : null;
        $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        return ['status' => $status, 'body' => is_string($out) ? substr($out, 0, 20000) : '', 'error' => $err, 'ms' => (int)((microtime(true) - $t0) * 1000)];
    }

    /** Throws ApiException(422) unless the URL is https (or http when allowed) and every resolved address is public. */
    public static function assertPublic(string $url): void
    {
        $allowPrivate = (bool)Config::get('integrations.allow_private', false) || getenv('SAIP_ALLOW_PRIVATE_WEBHOOKS') === '1';
        $p = parse_url($url);
        $scheme = strtolower($p['scheme'] ?? '');
        if (!$p || empty($p['host']) || !in_array($scheme, ['https', 'http'], true)) throw new ApiException(422, 'validation_failed', 'URL must start with https://', ['url' => 'invalid']);
        if ($scheme === 'http' && !$allowPrivate && !Config::get('integrations.allow_http', false)) throw new ApiException(422, 'validation_failed', 'Plain http:// is not allowed. Use https://.', ['url' => 'https required']);
        if (!empty($p['user']) || !empty($p['pass'])) throw new ApiException(422, 'validation_failed', 'Credentials in the URL are not allowed.', ['url' => 'invalid']);
        if ($allowPrivate) return;
        $host = trim($p['host'], '[]');
        $ips = filter_var($host, FILTER_VALIDATE_IP) ? [$host] : array_merge(array_column(@dns_get_record($host, DNS_A) ?: [], 'ip'), array_column(@dns_get_record($host, DNS_AAAA) ?: [], 'ipv6'));
        if (!$ips) throw new ApiException(422, 'validation_failed', 'The host name does not resolve.', ['url' => 'unresolvable']);
        foreach ($ips as $ip) {
            if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                throw new ApiException(422, 'validation_failed', 'The destination resolves to a private or reserved address, which is not allowed.', ['url' => 'private address']);
            }
        }
    }
}
