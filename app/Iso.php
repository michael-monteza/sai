<?php
declare(strict_types=1);

namespace Saip;

/** ISO/IEC 42001 readiness scoring and computed evidence. */
final class Iso
{
    public static function tier(int $score): array
    {
        return match (true) {
            $score >= 85 => ['Tier 5: Audit-Ready', 'Comprehensive AIMS operational; ready for Stage 1 & Stage 2 external certification.'],
            $score >= 65 => ['Tier 4: Managed & Evidenced', 'Controls largely evidenced; ready for a Stage 1 readiness review.'],
            $score >= 45 => ['Tier 3: Defined', 'Policies published; inventory exists; technical enforcement in progress.'],
            $score >= 25 => ['Tier 2: Developing', 'Initial acceptable use policy drafted; limited automated discovery.'],
            default      => ['Tier 1: Ad Hoc', 'Unsanctioned AI widespread; no formal AI management system evidenced yet.'],
        };
    }

    public static function summary(int $tenantId): array
    {
        $controls = Db::all('SELECT * FROM iso_controls WHERE tenant_id = ? ORDER BY sort_order', [$tenantId]);
        $total = count($controls);
        $pass = count(array_filter($controls, static fn ($c) => (int)$c['compliant'] === 1));
        $score = $total ? (int)round($pass / $total * 100) : 0;
        [$name, $desc] = self::tier($score);
        return ['controls' => $controls, 'total' => $total, 'passed' => $pass, 'score' => $score, 'tier' => $name, 'tier_desc' => $desc];
    }

    /** Evidence records derived from live data (nothing is hand-entered or pre-claimed). */
    public static function evidence(int $tenantId): array
    {
        $svc = Db::one('SELECT COUNT(*) n, MAX(updated_at) last, SUM(risk_score > 0) scored FROM ai_services WHERE tenant_id = ? AND active = 1', [$tenantId]);
        $blocked = (int)Db::val("SELECT COUNT(*) FROM audit_logs WHERE tenant_id = ? AND action LIKE 'registry\_%'", [$tenantId]);
        $audit = Db::val('SELECT MAX(timestamp) FROM audit_logs WHERE tenant_id = ?', [$tenantId]);
        $evt = Db::val('SELECT MAX(event_timestamp) FROM ai_usage_events WHERE tenant_id = ?', [$tenantId]);
        $now = gmdate('Y-m-d H:i:s');
        $n = (int)$svc['n'];
        return [
            ['standard_ref' => 'ISO 42001 cl. 8.2',   'artifact' => 'AI inventory & system owner register',  'source' => 'SAIP inventory + collectors', 'verified_at' => $svc['last'] ?? $now, 'status' => $n > 0 ? 'VERIFIED' : 'PENDING'],
            ['standard_ref' => 'ISO 42001 cl. 6.1.2', 'artifact' => 'AI risk scoring records',               'source' => 'SAIP risk engine',            'verified_at' => $svc['last'] ?? $now, 'status' => ($n > 0 && (int)$svc['scored'] === $n) ? 'VERIFIED' : 'PENDING'],
            ['standard_ref' => 'ISO 42001 Annex A.6', 'artifact' => 'AI service & DNS registry change history', 'source' => 'SAIP registry audit trail', 'verified_at' => $now,               'status' => $blocked > 0 ? 'VERIFIED' : 'PENDING'],
            ['standard_ref' => 'ISO 42001 Annex A.7', 'artifact' => 'Data classification per AI service',    'source' => 'SAIP inventory',              'verified_at' => $svc['last'] ?? $now, 'status' => $n > 0 ? 'VERIFIED' : 'PENDING'],
            ['standard_ref' => 'ISO 42001 Annex A.5', 'artifact' => 'Risk treatment audit trail',            'source' => 'SAIP audit log',              'verified_at' => $audit ?? $now,      'status' => $audit ? 'VERIFIED' : 'PENDING'],
            ['standard_ref' => 'ISO 42001 Annex A.9', 'artifact' => 'Endpoint telemetry received',           'source' => 'Sysmon collectors',           'verified_at' => $evt ?? $now,        'status' => $evt ? 'VERIFIED' : 'PENDING'],
        ];
    }
}
