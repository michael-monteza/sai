<?php
declare(strict_types=1);

namespace Saip;

/** Writes platform events to the outbox so SIEM / webhook integrations and the SIEM pull API can deliver them. Cheap no-op when a company has none. */
final class EventBus
{
    /** type => description (also the set of types an integration can subscribe to). */
    public const TYPES = [
        'audit.event' => 'Audit log entries (sign-ins, changes, exports, access denials)',
        'shadow_ai.detected' => 'An unsanctioned or under-review AI service is seen on a workstation for the first time',
        'discovery.new_domain' => 'A new AI-like hostname appears in Domain Discovery',
        'usage.event' => 'Every observed AI usage event from collectors (high volume)',
    ];
    private static array $on = [];

    public static function active(int $tenantId): bool
    {
        return self::$on[$tenantId] ??= (bool)(Db::val('SELECT 1 FROM integrations WHERE tenant_id = ? AND active = 1 LIMIT 1', [$tenantId]) || Db::val('SELECT 1 FROM api_tokens WHERE tenant_id = ? AND revoked = 0 LIMIT 1', [$tenantId]));
    }

    public static function reset(): void { self::$on = []; }

    public static function emit(int $tenantId, string $type, array $data): void
    {
        if (!self::active($tenantId)) return;
        try {
            Db::run('INSERT INTO event_outbox (tenant_id, type, payload) VALUES (?,?,?)', [$tenantId, $type, json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE)]);
        } catch (\Throwable $e) {
            error_log('[SAIP] outbox insert failed: ' . $e->getMessage());   // never break the request that produced the event
        }
    }
}
