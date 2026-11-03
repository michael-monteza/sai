<?php
declare(strict_types=1);

namespace Saip;

/**
 * AI adoption analytics. Purpose: find enablement/training opportunities, NOT to rank or penalise people.
 * Score (0-100) = active days 40 + distinct AI services 20 + event frequency 25 + sanctioned-service activity 15,
 * each component capped at its configurable target. Observed DNS telemetry only.
 */
final class Adoption
{
    public const DEFAULTS = [
        'adopt_window_days' => 30, 'adopt_days_target' => 15, 'adopt_services_target' => 3,
        'adopt_events_target' => 300, 'adopt_sanctioned_target' => 50, 'adopt_low_max' => 25, 'adopt_high_min' => 60,
    ];
    private const LIMITS = [
        'adopt_window_days' => [7, 180], 'adopt_days_target' => [1, 90], 'adopt_services_target' => [1, 20],
        'adopt_events_target' => [1, 100000], 'adopt_sanctioned_target' => [1, 100000], 'adopt_low_max' => [1, 99], 'adopt_high_min' => [2, 100],
    ];

    public static function settings(int $t): array
    {
        $s = self::DEFAULTS;
        foreach (Db::all("SELECT setting_key, setting_value FROM settings WHERE tenant_id = ? AND setting_key LIKE 'adopt\\_%'", [$t]) as $r) {
            if (isset($s[$r['setting_key']])) $s[$r['setting_key']] = (int)$r['setting_value'];
        }
        return $s;
    }

    /** Validates and stores thresholds. @return array<string,int> */
    public static function save(int $t, array $in): array
    {
        $s = self::settings($t);
        foreach (self::LIMITS as $k => [$min, $max]) {
            if (!array_key_exists($k, $in)) continue;
            if (!is_numeric($in[$k]) || (int)$in[$k] != $in[$k] || $in[$k] < $min || $in[$k] > $max) {
                throw new ApiException(422, 'validation_failed', "$k must be a whole number between $min and $max.", [$k => 'invalid']);
            }
            $s[$k] = (int)$in[$k];
        }
        if ($s['adopt_low_max'] >= $s['adopt_high_min']) {
            throw new ApiException(422, 'validation_failed', 'The Low ceiling must be below the High threshold.');
        }
        foreach (self::DEFAULTS as $k => $_) {
            Db::run('INSERT INTO settings (tenant_id, setting_key, setting_value) VALUES (?,?,?) ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)', [$t, $k, (string)$s[$k]]);
        }
        return $s;
    }

    public static function level(int $events, int $score, array $s): string
    {
        return $events === 0 ? 'None' : ($score < $s['adopt_low_max'] ? 'Low' : ($score < $s['adopt_high_min'] ? 'Moderate' : 'High'));
    }

    public static function score(int $days, int $svc, int $events, int $sanc, array $s): int
    {
        $p = min($days / $s['adopt_days_target'], 1) * 40 + min($svc / $s['adopt_services_target'], 1) * 20
           + min($events / $s['adopt_events_target'], 1) * 25 + min($sanc / $s['adopt_sanctioned_target'], 1) * 15;
        return (int)round($p);
    }

    /** @return array{settings:array,workstations:list<array>,departments:list<array>,summary:array,weekly:list<array>,monthly:list<array>} */
    public static function compute(int $t): array
    {
        $s = self::settings($t);
        $w = (int)$s['adopt_window_days'];
        $rows = Db::all(
            "SELECT c.computer_name, COALESCE(NULLIF(i.department,''),'Unmapped') department,
                    COALESCE(a.ev,0) events, COALESCE(a.days,0) active_days, COALESCE(a.svc,0) services, COALESCE(a.sanc,0) sanctioned_events, a.last_event
             FROM collectors c
             LEFT JOIN employee_inventory i ON i.tenant_id = c.tenant_id AND i.computer_name = c.computer_name
             LEFT JOIN (SELECT e.computer_name, COUNT(*) ev, COUNT(DISTINCT DATE(e.event_timestamp)) days, COUNT(DISTINCT e.ai_service_id) svc,
                               SUM(sv.sanction_status = 'sanctioned') sanc, MAX(e.event_timestamp) last_event
                        FROM ai_usage_events e JOIN ai_services sv ON sv.id = e.ai_service_id
                        WHERE e.tenant_id = ? AND e.event_timestamp >= UTC_TIMESTAMP() - INTERVAL $w DAY GROUP BY e.computer_name) a ON a.computer_name = c.computer_name
             WHERE c.tenant_id = ? AND c.status = 'authorized' ORDER BY c.computer_name", [$t, $t]);

        $levels = ['None' => 0, 'Low' => 0, 'Moderate' => 0, 'High' => 0];
        $dept = [];
        foreach ($rows as &$r) {
            $r['score'] = self::score((int)$r['active_days'], (int)$r['services'], (int)$r['events'], (int)$r['sanctioned_events'], $s);
            $r['level'] = self::level((int)$r['events'], $r['score'], $s);
            $levels[$r['level']]++;
            $d = &$dept[$r['department']];
            $d ??= ['department' => $r['department'], 'workstations' => 0, 'score_sum' => 0, 'None' => 0, 'Low' => 0, 'Moderate' => 0, 'High' => 0, 'events' => 0, 'sanctioned_events' => 0, 'services' => []];
            $d['workstations']++; $d['score_sum'] += $r['score']; $d[$r['level']]++;
            $d['events'] += (int)$r['events']; $d['sanctioned_events'] += (int)$r['sanctioned_events'];
            unset($d);
        }
        unset($r);

        $departments = array_values(array_map(static function ($d) {
            $d['avg_score'] = $d['workstations'] ? (int)round($d['score_sum'] / $d['workstations']) : 0;
            $d['active_pct'] = $d['workstations'] ? (int)round(($d['workstations'] - $d['None']) / $d['workstations'] * 100) : 0;
            $d['sanctioned_pct'] = $d['events'] ? (int)round($d['sanctioned_events'] / $d['events'] * 100) : null;
            unset($d['score_sum'], $d['services']);
            return $d;
        }, $dept));
        usort($departments, static fn ($a, $b) => $b['avg_score'] <=> $a['avg_score']);

        $weekly = Db::all("SELECT YEARWEEK(event_timestamp, 3) wk, MIN(DATE(event_timestamp)) week_start, COUNT(DISTINCT computer_name) active_workstations, COUNT(*) events
                           FROM ai_usage_events WHERE tenant_id = ? AND event_timestamp >= UTC_TIMESTAMP() - INTERVAL 84 DAY GROUP BY wk ORDER BY wk", [$t]);
        $monthly = Db::all("SELECT DATE_FORMAT(event_timestamp, '%Y-%m') month, COUNT(DISTINCT computer_name) active_workstations, COUNT(*) events
                            FROM ai_usage_events WHERE tenant_id = ? AND event_timestamp >= UTC_TIMESTAMP() - INTERVAL 6 MONTH GROUP BY month ORDER BY month", [$t]);
        $n = count($rows);
        return [
            'settings' => $s, 'workstations' => $rows, 'departments' => $departments,
            'summary' => ['monitored' => $n, 'levels' => $levels, 'active_pct' => $n ? (int)round(($n - $levels['None']) / $n * 100) : 0,
                          'avg_score' => $n ? (int)round(array_sum(array_column($rows, 'score')) / $n) : 0],
            'weekly' => $weekly, 'monthly' => $monthly,
        ];
    }
}
