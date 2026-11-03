<?php
declare(strict_types=1);

namespace Saip;

/**
 * Per-tenant AI domain registry: matching rules plus the config version collectors sync against.
 * A rule is [service_id, matching_rule ('exact'|'subdomain'), excluded (bool)].
 */
final class DomainRegistry
{
    /** @return array<string,array{0:int,1:string,2:bool}> domain => rule (active domains of non-archived services) */
    public static function load(int $tenantId): array
    {
        $map = [];
        foreach (Db::all(
            'SELECT d.domain, d.ai_service_id, d.matching_rule, s.sanction_status FROM ai_domains d
             JOIN ai_services s ON s.id = d.ai_service_id
             WHERE d.tenant_id = ? AND d.active = 1 AND s.active = 1 AND s.archived = 0', [$tenantId]) as $r) {
            $map[strtolower($r['domain'])] = [(int)$r['ai_service_id'], $r['matching_rule'], $r['sanction_status'] === 'excluded'];
        }
        return $map;
    }

    /**
     * Returns [service_id, excluded] or null. Exact rules only match the host itself;
     * subdomain rules match the host or any parent (a.b.example.com -> b.example.com -> example.com).
     * @return array{0:int,1:bool}|null
     */
    public static function match(string $host, array $map): ?array
    {
        if (isset($map[$host])) {
            return [$map[$host][0], $map[$host][2]];
        }
        $labels = explode('.', $host);
        array_shift($labels);
        while (count($labels) >= 2) {
            $candidate = implode('.', $labels);
            if (isset($map[$candidate]) && $map[$candidate][1] === 'subdomain') {
                return [$map[$candidate][0], $map[$candidate][2]];
            }
            array_shift($labels);
        }
        return null;
    }

    public static function version(int $tenantId): int
    {
        return (int)Db::val('SELECT config_version FROM tenants WHERE id = ?', [$tenantId]);
    }

    /** Call after any change that affects what collectors should watch. */
    public static function bump(int $tenantId): int
    {
        Db::run('UPDATE tenants SET config_version = config_version + 1 WHERE id = ?', [$tenantId]);
        return self::version($tenantId);
    }

    /** Accepts "Example.com", "https://x.example.com/path", "*.example.com". Returns [host, impliedRule|null] or null. */
    public static function normalize(mixed $input): ?array
    {
        if (!is_string($input)) return null;
        $v = strtolower(trim($input));
        $rule = null;
        if (str_starts_with($v, '*.')) { $v = substr($v, 2); $rule = 'subdomain'; }
        $v = preg_replace('#^[a-z][a-z0-9+.-]*://#', '', $v);
        $v = preg_split('#[/?\#:]#', $v, 2)[0];
        $v = rtrim($v, '.');
        if (filter_var($v, FILTER_VALIDATE_IP)) return null;
        $h = Validator::hostname($v);
        return $h === null ? null : [$h, $rule];
    }

    /** Monitoring options delivered to collectors (stored as settings rows, defaults here). */
    public static function monitoring(int $tenantId): array
    {
        $s = [];
        foreach (Db::all("SELECT setting_key, setting_value FROM settings WHERE tenant_id = ? AND setting_key LIKE 'mon\\_%'", [$tenantId]) as $r) {
            $s[$r['setting_key']] = $r['setting_value'];
        }
        $hints = array_values(array_filter(array_map('trim', explode(',', (string)($s['mon_discovery_hints'] ?? 'ai,gpt,llm,copilot,chatbot,claude,gemini')))));
        return [
            'dns_events'       => true,
            'network_events'   => ($s['mon_network_events'] ?? '0') === '1',
            'discovery'        => ($s['mon_discovery'] ?? '1') === '1',
            'discovery_hints'  => $hints,
            'interval_minutes' => max(1, (int)($s['mon_interval_minutes'] ?? 5)),
        ];
    }
}
