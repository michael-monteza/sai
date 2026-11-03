<?php
declare(strict_types=1);

namespace Saip;

/**
 * IP intelligence for Sysmon network connections (EID 3) that carry no usable host name.
 * Registered FQDNs are resolved to addresses; an address identifies a service only when it is dedicated: not inside a shared edge network
 * (CDNs such as Cloudflare/Google front ends, config/shared_ip_ranges.php) and not returned for more than one registered service.
 * Connections to shared addresses are counted as "ambiguous" and never stored as usage, because they cannot prove which site was visited.
 */
final class IpIntel
{
    private static ?array $ranges = null;
    private static array $memo = [];

    /** @return array<string,list<string>> */
    private static function ranges(): array { return self::$ranges ??= require SAIP_ROOT . '/config/shared_ip_ranges.php'; }

    /** Canonical text form (IPv6 is compressed, lower-case) so "2607:6bc0:0:0:0:0:0:10" and "2607:6bc0::10" are the same address. */
    public static function canonical(string $ip): string
    {
        $b = @inet_pton($ip);
        return $b === false ? $ip : (string)inet_ntop($b);
    }

    /** Name of the shared network the address belongs to, or null. */
    public static function sharedNetwork(string $ip): ?string
    {
        $bin = @inet_pton($ip);
        if ($bin === false) return null;
        foreach (self::ranges() as $name => $cidrs) {
            foreach ($cidrs as $c) {
                [$net, $bits] = explode('/', $c);
                $nb = @inet_pton($net);
                if ($nb === false || strlen($nb) !== strlen($bin)) continue;
                $full = intdiv((int)$bits, 8); $rem = (int)$bits % 8;
                if (substr($bin, 0, $full) !== substr($nb, 0, $full)) continue;
                if ($rem === 0 || ((ord($bin[$full]) ^ ord($nb[$full])) >> (8 - $rem)) === 0) return $name;
            }
        }
        return null;
    }

    /** Reverse-DNS check for CDN / platform addresses that are not in the range list. Results are cached for a week; $lookup=false uses the cache only (fast). */
    public static function sharedByName(string $ip, bool $lookup = true): ?string
    {
        $row = Db::one('SELECT ptr FROM ip_ptr_cache WHERE ip = ? AND checked_at >= UTC_TIMESTAMP() - INTERVAL 7 DAY', [$ip]);
        if ($row === null) {
            if (!$lookup) return null;
            $h = @gethostbyaddr($ip);
            $ptr = is_string($h) && $h !== $ip ? strtolower($h) : null;
            Db::run('INSERT INTO ip_ptr_cache (ip, ptr, checked_at) VALUES (?,?,UTC_TIMESTAMP()) ON DUPLICATE KEY UPDATE ptr = VALUES(ptr), checked_at = UTC_TIMESTAMP()', [$ip, $ptr]);
        } else {
            $ptr = $row['ptr'];
        }
        return $ptr !== null && preg_match('/(cloudfront|akamai|edgekey|edgesuite|fastly|cloudflare|azureedge|azurefd|trafficmanager|1e100|googleusercontent|awsglobalaccelerator|stackpathcdn|incapdns|cdn77|b-cdn|vercel|netlify|herokuapp|herokudns|github\.io|azurewebsites|appspot)/', $ptr, $m) ? 'name:' . $m[1] : null;
    }

    /** Resolves the company's active registry domains and rebuilds ip_map. @return array{domains:int,ips:int,usable:int,shared:int} */
    public static function refresh(int $t, bool $lookupPtr = true): array
    {
        @set_time_limit(300);
        $rows = Db::all('SELECT d.domain, d.ai_service_id, LOWER(s.provider) provider FROM ai_domains d JOIN ai_services s ON s.id = d.ai_service_id
                         WHERE d.tenant_id = ? AND d.active = 1 AND s.active = 1 AND s.archived = 0 AND s.sanction_status <> "excluded"', [$t]);
        $map = [];   // ip => [domain => service id]
        foreach ($rows as $r) {
            $host = $r['domain'];
            foreach (array_merge(@dns_get_record($host, DNS_A) ?: [], @dns_get_record($host, DNS_AAAA) ?: []) as $rec) {
                $ip = $rec['ip'] ?? $rec['ipv6'] ?? null;
                if ($ip && filter_var($ip, FILTER_VALIDATE_IP)) $map[self::canonical($ip)][$host] = [(int)$r['ai_service_id'], $r['provider']];
            }
        }
        // Classify first (reverse-DNS lookups can be slow); the database transaction below is then short.
        $class = [];
        foreach ($map as $ip => $domains) {
            $class[$ip] = self::sharedNetwork($ip) ?? self::sharedByName($ip, $lookupPtr);
        }
        $pdo = Db::pdo(); $pdo->beginTransaction();
        try {
            Db::run('DELETE FROM ip_map WHERE tenant_id = ?', [$t]);
            $usable = $shared = 0;
            foreach ($map as $ip => $domains) {
                $net = $class[$ip];
                $multi = count(array_unique(array_column($domains, 1))) > 1;   // several services of the SAME provider (claude.ai + api.anthropic.com) still identify that provider
                $isShared = $net !== null || $multi;
                $isShared ? $shared++ : $usable++;
                foreach ($domains as $d => [$sid]) {
                    Db::run('INSERT INTO ip_map (tenant_id, ip, ai_service_id, domain, shared, reason) VALUES (?,?,?,?,?,?)', [$t, $ip, $sid, $d, $isShared ? 1 : 0, $net !== null ? mb_substr(str_starts_with($net, 'name:') ? $net : 'network:' . $net, 0, 40) : ($multi ? 'several services' : null)]);
                }
            }
            $pdo->commit();
        } catch (\Throwable $e) { $pdo->rollBack(); throw $e; }
        self::$memo = [];
        return ['domains' => count($rows), 'ips' => count($map), 'usable' => $usable, 'shared' => $shared];
    }

    /** Dedicated addresses for the collector: [{ip, service_id}], refreshed within the last 3 days. @return list<array{ip:string,service_id:int}> */
    public static function rules(int $t): array
    {
        return array_map(static fn ($r) => ['ip' => $r['ip'], 'service_id' => (int)$r['ai_service_id']],
            Db::all('SELECT ip, MIN(ai_service_id) ai_service_id FROM ip_map WHERE tenant_id = ? AND shared = 0 AND resolved_at >= UTC_TIMESTAMP() - INTERVAL 3 DAY GROUP BY ip ORDER BY ip LIMIT 5000', [$t]));
    }

    /** @return array{service_id:int,shared:bool}|null null = unknown address. Shared addresses return shared=true. */
    public static function lookup(int $t, string $ip): ?array
    {
        $ip = self::canonical($ip);
        $key = $t . '|' . $ip;
        if (array_key_exists($key, self::$memo)) return self::$memo[$key];
        $net = self::sharedNetwork($ip);
        $row = Db::one('SELECT MIN(ai_service_id) ai_service_id, MAX(shared) shared FROM ip_map WHERE tenant_id = ? AND ip = ? HAVING COUNT(*) > 0', [$t, $ip]);
        return self::$memo[$key] = $net !== null ? ['service_id' => 0, 'shared' => true] : ($row ? ['service_id' => (int)$row['ai_service_id'], 'shared' => (bool)$row['shared']] : null);
    }

    /** @return array{ips:int,usable:int,shared:int,services:int,refreshed:?string} */
    public static function status(int $t): array
    {
        $r = Db::one('SELECT COUNT(DISTINCT ip) ips, COUNT(DISTINCT IF(shared = 0, ip, NULL)) usable, COUNT(DISTINCT IF(shared = 1, ip, NULL)) shared, COUNT(DISTINCT IF(shared = 0, ai_service_id, NULL)) services, MAX(resolved_at) refreshed FROM ip_map WHERE tenant_id = ?', [$t]);
        return ['ips' => (int)$r['ips'], 'usable' => (int)$r['usable'], 'shared' => (int)$r['shared'], 'services' => (int)$r['services'], 'refreshed' => $r['refreshed']];
    }
}
