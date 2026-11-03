<?php
declare(strict_types=1);

namespace Saip;

use Saip\Security\Secrets;

/** Platform-wide settings (not per company), with encrypted secrets. */
final class PlatformSettings
{
    private static ?array $cache = null;

    private static function all(): array
    {
        if (self::$cache === null) {
            self::$cache = [];
            foreach (Db::all('SELECT name, value, secret FROM platform_settings') as $r) self::$cache[$r['name']] = $r;
        }
        return self::$cache;
    }

    public static function get(string $name, ?string $default = null): ?string
    {
        $r = self::all()[$name] ?? null;
        if (!$r || $r['value'] === null || $r['value'] === '') return $default;
        return (int)$r['secret'] === 1 ? Secrets::decrypt($r['value']) : $r['value'];
    }

    public static function has(string $name): bool { return self::get($name) !== null; }

    public static function set(string $name, ?string $value, string $actor, bool $secret = false): void
    {
        $stored = $value === null || $value === '' ? null : ($secret ? Secrets::encrypt($value) : $value);
        Db::run('INSERT INTO platform_settings (name, value, secret, updated_at, updated_by) VALUES (?,?,?,UTC_TIMESTAMP(),?)
                 ON DUPLICATE KEY UPDATE value = VALUES(value), secret = VALUES(secret), updated_at = UTC_TIMESTAMP(), updated_by = VALUES(updated_by)', [$name, $stored, $secret ? 1 : 0, $actor]);
        self::$cache = null;
    }
}
