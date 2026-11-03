<?php
declare(strict_types=1);

namespace Saip;

/**
 * Read-only reporting over observed telemetry. Every query is tenant-scoped and bound by a day window.
 * Figures are observed DNS / connection events, not verified sessions or time spent.
 */
final class Reports
{
    public const LIMITATIONS = [
        'DNS events show that a hostname was resolved on a workstation, not that a session took place or how long it lasted.',
        'Event ID 3 records only the destination IP (and a hostname when available); it is optional and off by default.',
        'Only Windows workstations running Sysmon and an authorized collector are covered. Personal devices, mobile, browsers with encrypted DNS and unlisted tools are not.',
        'Activity on a workstation is not attributed to a person; figures are for governance and enablement, not employee monitoring.',
        'A hostname absent from the registry is not counted as AI usage until it is classified in Domain Discovery.',
    ];

    /** name => [title, description, columns key=>label] */
    public static function catalog(): array
    {
        return [
            'usage-by-service' => ['AI usage by service', 'Observed activity per registered AI service.', [
                'service_name' => 'Service', 'provider' => 'Provider', 'sanction_status' => 'Classification', 'dns_events' => 'DNS events',
                'connections' => 'Network connections', 'workstations' => 'Workstations', 'first_observed' => 'First observed (UTC)', 'last_observed' => 'Last observed (UTC)']],
            'sanctioned-vs-unsanctioned' => ['Sanctioned vs unsanctioned', 'Activity grouped by service classification.', [
                'sanction_status' => 'Classification', 'services' => 'Services observed', 'dns_events' => 'DNS events', 'workstations' => 'Workstations', 'share_pct' => 'Share of events %']],
            'top-domains' => ['Top domains', 'Most-observed registered domains.', [
                'domain' => 'Domain', 'service_name' => 'Service', 'sanction_status' => 'Classification', 'dns_events' => 'DNS events', 'workstations' => 'Workstations', 'last_observed' => 'Last observed (UTC)']],
            'network-activity' => ['Network activity (Event ID 3)', 'Connections matched to registered services.', [
                'service_name' => 'Service', 'destination_host' => 'Destination host', 'destination_port' => 'Port', 'match_basis' => 'Matched by', 'connections' => 'Connections', 'workstations' => 'Workstations', 'last_observed' => 'Last observed (UTC)']],
            'workstation-activity' => ['Workstation activity', 'Observed events per monitored workstation.', [
                'computer_name' => 'Computer', 'services' => 'AI services', 'dns_events' => 'DNS events', 'sanctioned_events' => 'Sanctioned events', 'unsanctioned_events' => 'Unsanctioned / under review events', 'last_observed' => 'Last observed (UTC)']],
            'discovery' => ['Domain discovery', 'Hostnames reported that are not in the registry.', [
                'domain' => 'Domain', 'status' => 'Status', 'hit_count' => 'Hits', 'workstations' => 'Workstations', 'first_seen' => 'First seen (UTC)', 'last_seen' => 'Last seen (UTC)']],
            'collector-health' => ['Collector health', 'Status and sync state of each collector.', [
                'computer_name' => 'Computer', 'status' => 'Status', 'collector_version' => 'Version', 'last_seen' => 'Last seen (UTC)', 'config_version_applied' => 'Config version',
                'spool_depth' => 'Spool depth', 'failed_submissions' => 'Failed submissions', 'last_error' => 'Last error']],
            'registry' => ['AI services & DNS registry', 'Registered services with their domains and matching rules.', [
                'service_name' => 'Service', 'provider' => 'Provider', 'sanction_status' => 'Classification', 'domain' => 'Domain', 'domain_type' => 'Domain type', 'matching_rule' => 'Matching', 'active' => 'Active', 'archived' => 'Archived']],
        ];
    }

    public static function days(mixed $v): int
    {
        $d = is_numeric($v) ? (int)$v : 30;
        return max(1, min(365, $d));
    }

    /** @return list<array<string,mixed>> */
    public static function rows(string $name, int $t, int $days): array
    {
        $since = 'UTC_TIMESTAMP() - INTERVAL ? DAY';
        switch ($name) {
            case 'usage-by-service':
                return Db::all("SELECT s.service_name, s.provider, s.sanction_status,
                        COALESCE(u.ev,0) dns_events, COALESCE(n.c,0) connections, COALESCE(u.ws,0) workstations, u.first_observed, u.last_observed
                    FROM ai_services s
                    LEFT JOIN (SELECT ai_service_id, COUNT(*) ev, COUNT(DISTINCT computer_name) ws, MIN(event_timestamp) first_observed, MAX(event_timestamp) last_observed
                               FROM ai_usage_events WHERE tenant_id = ? AND event_timestamp >= $since GROUP BY ai_service_id) u ON u.ai_service_id = s.id
                    LEFT JOIN (SELECT ai_service_id, COUNT(*) c FROM network_connection_events WHERE tenant_id = ? AND event_timestamp >= $since GROUP BY ai_service_id) n ON n.ai_service_id = s.id
                    WHERE s.tenant_id = ? AND s.archived = 0 AND (u.ev IS NOT NULL OR n.c IS NOT NULL)
                    ORDER BY dns_events DESC, s.service_name", [$t, $days, $t, $days, $t]);
            case 'sanctioned-vs-unsanctioned':
                $rows = Db::all("SELECT s.sanction_status, COUNT(DISTINCT s.id) services, COUNT(*) dns_events, COUNT(DISTINCT e.computer_name) workstations
                    FROM ai_usage_events e JOIN ai_services s ON s.id = e.ai_service_id
                    WHERE e.tenant_id = ? AND e.event_timestamp >= $since GROUP BY s.sanction_status ORDER BY dns_events DESC", [$t, $days]);
                $total = array_sum(array_column($rows, 'dns_events'));
                foreach ($rows as &$r) $r['share_pct'] = $total ? round($r['dns_events'] / $total * 100, 1) : 0;
                return $rows;
            case 'top-domains':
                return Db::all("SELECT e.query_domain domain, s.service_name, s.sanction_status, COUNT(*) dns_events, COUNT(DISTINCT e.computer_name) workstations, MAX(e.event_timestamp) last_observed
                    FROM ai_usage_events e JOIN ai_services s ON s.id = e.ai_service_id
                    WHERE e.tenant_id = ? AND e.event_timestamp >= $since GROUP BY e.query_domain, s.service_name, s.sanction_status ORDER BY dns_events DESC LIMIT 500", [$t, $days]);
            case 'network-activity':
                return Db::all("SELECT s.service_name, COALESCE(n.destination_host, n.destination_ip) destination_host, n.destination_port, n.match_basis,
                        COUNT(*) connections, COUNT(DISTINCT n.computer_name) workstations, MAX(n.event_timestamp) last_observed
                    FROM network_connection_events n LEFT JOIN ai_services s ON s.id = n.ai_service_id
                    WHERE n.tenant_id = ? AND n.event_timestamp >= $since GROUP BY s.service_name, destination_host, n.destination_port, n.match_basis ORDER BY connections DESC LIMIT 500", [$t, $days]);
            case 'workstation-activity':
                return Db::all("SELECT e.computer_name, COUNT(DISTINCT e.ai_service_id) services, COUNT(*) dns_events,
                        SUM(s.sanction_status = 'sanctioned') sanctioned_events, SUM(s.sanction_status <> 'sanctioned') unsanctioned_events, MAX(e.event_timestamp) last_observed
                    FROM ai_usage_events e JOIN ai_services s ON s.id = e.ai_service_id
                    WHERE e.tenant_id = ? AND e.event_timestamp >= $since GROUP BY e.computer_name ORDER BY dns_events DESC", [$t, $days]);
            case 'discovery':
                return Db::all("SELECT d.domain, d.status, d.hit_count, (SELECT COUNT(*) FROM discovered_domain_hosts h WHERE h.discovered_id = d.id) workstations, d.first_seen, d.last_seen
                    FROM discovered_domains d WHERE d.tenant_id = ? AND d.last_seen >= $since ORDER BY d.hit_count DESC LIMIT 1000", [$t, $days]);
            case 'collector-health':
                return Db::all('SELECT computer_name, status, collector_version, last_seen, config_version_applied, spool_depth, failed_submissions, last_error
                    FROM collectors WHERE tenant_id = ? ORDER BY computer_name', [$t]);
            case 'registry':
                return Db::all('SELECT s.service_name, s.provider, s.sanction_status, d.domain, d.domain_type, d.matching_rule, d.active, s.archived
                    FROM ai_services s LEFT JOIN ai_domains d ON d.ai_service_id = s.id WHERE s.tenant_id = ? ORDER BY s.service_name, d.domain', [$t]);
        }
        throw new ApiException(404, 'not_found', 'Unknown report.');
    }

    /** Dashboard summary: KPIs, trend, top services, coverage and limitations. */
    public static function summary(int $t, int $days): array
    {
        $since = 'UTC_TIMESTAMP() - INTERVAL ? DAY';
        $cls = Db::all("SELECT s.sanction_status st, COUNT(*) ev, COUNT(DISTINCT e.computer_name) ws FROM ai_usage_events e JOIN ai_services s ON s.id = e.ai_service_id
            WHERE e.tenant_id = ? AND e.event_timestamp >= $since GROUP BY st", [$t, $days]);
        $ev = ['sanctioned' => 0, 'unsanctioned' => 0, 'under_review' => 0, 'excluded' => 0];
        foreach ($cls as $r) $ev[$r['st']] = (int)$r['ev'];
        $total = array_sum($ev);
        $tot = Db::one("SELECT COUNT(DISTINCT computer_name) ws, MAX(event_timestamp) last_event FROM ai_usage_events WHERE tenant_id = ? AND event_timestamp >= $since", [$t, $days]);
        $col = Db::one("SELECT SUM(status = 'authorized') authorized, SUM(status = 'authorized' AND last_seen >= UTC_TIMESTAMP() - INTERVAL 15 MINUTE) online,
                SUM(status = 'authorized' AND spool_depth > 0) buffering FROM collectors WHERE tenant_id = ?", [$t]);
        $authorized = (int)($col['authorized'] ?? 0);
        return [
            'days' => $days,
            'totals' => [
                'dns_events' => $total, 'workstations_with_activity' => (int)$tot['ws'], 'last_event' => $tot['last_event'],
                'sanctioned_events' => $ev['sanctioned'], 'unsanctioned_events' => $ev['unsanctioned'], 'under_review_events' => $ev['under_review'],
                'sanctioned_pct' => $total ? round($ev['sanctioned'] / $total * 100, 1) : null,
                'unsanctioned_pct' => $total ? round(($ev['unsanctioned'] + $ev['under_review']) / $total * 100, 1) : null,
                'network_connections' => (int)Db::val("SELECT COUNT(*) FROM network_connection_events WHERE tenant_id = ? AND event_timestamp >= $since", [$t, $days]),
                'new_discoveries' => (int)Db::val("SELECT COUNT(*) FROM discovered_domains WHERE tenant_id = ? AND status IN ('new','under_review')", [$t]),
            ],
            'trend' => Db::all("SELECT DATE(e.event_timestamp) d, SUM(s.sanction_status = 'sanctioned') sanctioned, SUM(s.sanction_status <> 'sanctioned') unsanctioned
                FROM ai_usage_events e JOIN ai_services s ON s.id = e.ai_service_id WHERE e.tenant_id = ? AND e.event_timestamp >= $since GROUP BY d ORDER BY d", [$t, $days]),
            'top_services' => array_slice(self::rows('usage-by-service', $t, $days), 0, 8),
            'coverage' => [
                'authorized_collectors' => $authorized, 'online' => (int)($col['online'] ?? 0), 'buffering' => (int)($col['buffering'] ?? 0),
                'network_events_enabled' => DomainRegistry::monitoring($t)['network_events'],
                'online_pct' => $authorized ? round((int)$col['online'] / $authorized * 100) : null,
            ],
            'limitations' => self::LIMITATIONS,
        ];
    }

    public static function retention(int $t): array
    {
        $s = ['retention_events_days' => 0, 'retention_discovery_days' => 0, 'retention_heartbeat_days' => 90];
        foreach (Db::all("SELECT setting_key, setting_value FROM settings WHERE tenant_id = ? AND setting_key LIKE 'retention\\_%'", [$t]) as $r) {
            if (isset($s[$r['setting_key']])) $s[$r['setting_key']] = (int)$r['setting_value'];
        }
        return $s;
    }

    public static function saveRetention(int $t, array $in): array
    {
        $s = self::retention($t);
        foreach ($s as $k => $_) {
            if (!array_key_exists($k, $in)) continue;
            if (!is_numeric($in[$k]) || (int)$in[$k] != $in[$k] || $in[$k] < 0 || $in[$k] > 3650) {
                throw new ApiException(422, 'validation_failed', "$k must be a whole number of days between 0 (keep forever) and 3650.", [$k => 'invalid']);
            }
            $s[$k] = (int)$in[$k];
            Db::run('INSERT INTO settings (tenant_id, setting_key, setting_value) VALUES (?,?,?) ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)', [$t, $k, (string)$s[$k]]);
        }
        return $s;
    }
}
