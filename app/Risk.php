<?php
declare(strict_types=1);

namespace Saip;

/** SAIP risk engine: weighted 0-100 score from data sensitivity, training exposure, vendor, identity and usage. */
final class Risk
{
    public const SENSITIVITY = ['Public' => 10, 'Internal' => 40, 'Confidential' => 75, 'Restricted / PII' => 95];

    public static function score(string $dataClass, int $training, int $vendor, int $identity, int $usage): int
    {
        $s = (self::SENSITIVITY[$dataClass] ?? 40) * 0.30 + $training * 0.20 + $vendor * 0.20 + $identity * 0.15 + $usage * 0.15;
        return (int)max(0, min(100, round($s)));
    }

    public static function level(int $score): string
    {
        return $score >= 75 ? 'Critical' : ($score >= 50 ? 'High' : ($score >= 25 ? 'Medium' : 'Low'));
    }

    /** Usage volume (0-100) from the last 30 days: 10 per distinct workstation + 1 per 20 observed events. */
    public static function usageVolume(int $workstations, int $events): int
    {
        return min(100, $workstations * 10 + intdiv($events, 20));
    }

    /** Recomputes usage_volume and risk_score for every service of a tenant. Returns count updated. */
    public static function recalculate(int $tenantId): int
    {
        $usage = [];
        foreach (Db::all(
            'SELECT ai_service_id, COUNT(*) ev, COUNT(DISTINCT computer_name) ws FROM ai_usage_events
             WHERE tenant_id = ? AND event_timestamp >= UTC_TIMESTAMP() - INTERVAL 30 DAY GROUP BY ai_service_id', [$tenantId]) as $r) {
            $usage[(int)$r['ai_service_id']] = self::usageVolume((int)$r['ws'], (int)$r['ev']);
        }
        $n = 0;
        foreach (Db::all('SELECT * FROM ai_services WHERE tenant_id = ?', [$tenantId]) as $s) {
            $uv = $usage[(int)$s['id']] ?? 0;
            $score = self::score($s['data_class'], (int)$s['training_exposure'], (int)$s['vendor_risk'], (int)$s['identity_risk'], $uv);
            Db::run('UPDATE ai_services SET usage_volume = ?, risk_score = ?, updated_at = UTC_TIMESTAMP() WHERE id = ?', [$uv, $score, $s['id']]);
            $n++;
        }
        return $n;
    }
}
