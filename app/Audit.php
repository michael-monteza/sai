<?php
declare(strict_types=1);

namespace Saip;

/** Append-only audit trail. The request context (client IP, request id) is attached automatically by RequestContext. */
final class Audit
{
    public static ?string $ip = null;
    public static ?string $requestId = null;

    public static function log(string $actor, string $action, ?string $record = null, array|string|null $details = null, ?int $tenantId = null,
                               ?array $before = null, ?array $after = null): void
    {
        if (is_array($details)) {
            $details = json_encode($details, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        }
        $enc = static fn (?array $a): ?string => $a === null ? null : json_encode($a, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        Db::run('INSERT INTO audit_logs (tenant_id, administrator, action, affected_record, details, before_json, after_json, ip_address, request_id) VALUES (?,?,?,?,?,?,?,?,?)',
            [$tenantId, mb_substr($actor, 0, 100), $action, $record === null ? null : mb_substr($record, 0, 255), $details, $enc($before), $enc($after), self::$ip, self::$requestId]);
        if ($tenantId !== null) {   // stream to SIEM / webhook integrations (no-op when the company has none)
            EventBus::emit($tenantId, 'audit.event', ['actor' => $actor, 'action' => $action, 'record' => $record, 'details' => $details, 'ip' => self::$ip, 'request_id' => self::$requestId]);
        }
    }
}
