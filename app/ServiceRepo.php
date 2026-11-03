<?php
declare(strict_types=1);

namespace Saip;

/** Inventory read model shared by the dashboard, inventory, registry and ISO export. */
final class ServiceRepo
{
    public const LIFE_TO_STATUS = [
        'Formally Sanctioned' => 'sanctioned', 'Under Security Evaluation' => 'under_review',
        'Shadow Usage Detected' => 'unsanctioned', 'Prohibited / Blocked' => 'unsanctioned', 'Decommissioned' => 'unsanctioned',
    ];
    public const DATA_CLASSES = ['Public', 'Internal', 'Confidential', 'Restricted / PII'];
    public const STATUSES = ['sanctioned', 'unsanctioned', 'under_review', 'excluded'];

    /** @return list<array<string,mixed>> */
    public static function rows(int $t, ?int $id = null): array
    {
        $rows = Db::all('SELECT s.*, COALESCE(u.ev,0) events_30d, COALESCE(u.ws,0) workstations_30d, u.last_seen
                FROM ai_services s
                LEFT JOIN (SELECT ai_service_id, SUM(event_timestamp >= UTC_TIMESTAMP() - INTERVAL 30 DAY) ev,
                                  COUNT(DISTINCT IF(event_timestamp >= UTC_TIMESTAMP() - INTERVAL 30 DAY, computer_name, NULL)) ws,
                                  MAX(event_timestamp) last_seen
                           FROM ai_usage_events WHERE tenant_id = ? GROUP BY ai_service_id) u ON u.ai_service_id = s.id
                WHERE s.tenant_id = ?' . ($id ? ' AND s.id = ?' : '') . ' ORDER BY s.risk_score DESC, s.service_name', $id ? [$t, $t, $id] : [$t, $t]);
        $dom = [];
        foreach (Db::all('SELECT id, ai_service_id, domain, blocked, domain_type, matching_rule, active, shared, notes, first_observed, last_observed,
                          (SELECT COUNT(*) FROM ai_usage_events e WHERE e.tenant_id = d.tenant_id AND e.query_domain = d.domain) hits
                          FROM ai_domains d WHERE tenant_id = ? ORDER BY domain', [$t]) as $d) {
            $dom[$d['ai_service_id']][] = $d;
        }
        foreach ($rows as &$r) {
            $r['domains'] = $dom[$r['id']] ?? [];
            $r['risk_level'] = Risk::level((int)$r['risk_score']);
            $r['data_sensitivity'] = Risk::SENSITIVITY[$r['data_class']] ?? 40;
            $r['in_inventory'] = self::inInventory($r);
        }
        return $rows;
    }

    /**
     * The AI Asset Inventory holds services the company actually has: usage detected by collectors, or entered by a person
     * (registered manually, from a staff request, classified from discovery, or sanctioned). Services that only exist as DNS
     * registry reference data (the preloaded catalogue and bulk imports) stay in AI Services & DNS Registry until they are detected or adopted.
     */
    public static function inInventory(array $s): bool
    {
        return $s['last_seen'] !== null || (int)($s['events_30d'] ?? 0) > 0 || in_array($s['source'], ['manual', 'discovered', 'request'], true) || $s['sanction_status'] === 'sanctioned';
    }

    /** Throws 409 when any domain already belongs to another service of this company. */
    public static function assertDomainsFree(int $t, array $domains, int $exceptServiceId): void
    {
        foreach ($domains as $d) {
            $other = Db::one('SELECT s.service_name FROM ai_domains x JOIN ai_services s ON s.id = x.ai_service_id WHERE x.tenant_id = ? AND x.domain = ? AND x.ai_service_id <> ?', [$t, $d, $exceptServiceId]);
            if ($other) throw new ApiException(409, 'domain_in_use', "$d is already assigned to {$other['service_name']}.");
        }
    }
}
