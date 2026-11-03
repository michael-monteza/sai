<?php
declare(strict_types=1);

namespace Saip\Security;

/** Permission lookup over config/rbac.php. */
final class Rbac
{
    private static ?array $cfg = null;

    private static function cfg(): array
    {
        return self::$cfg ??= require SAIP_ROOT . '/config/rbac.php';
    }

    public static function setting(string $k, mixed $default = null): mixed { return self::cfg()[$k] ?? $default; }
    public static function roles(): array { return self::cfg()['roles']; }
    public static function rank(string $role): int { return (int)(self::cfg()['roles'][$role]['rank'] ?? 0); }
    public static function valid(string $role): bool { return isset(self::cfg()['roles'][$role]); }

    public static function can(string $role, string $permission): bool
    {
        foreach (self::cfg()['roles'][$role]['permissions'] ?? [] as $p) {
            if ($p === '*' || $p === $permission || (str_ends_with($p, '.*') && str_starts_with($permission, substr($p, 0, -1)))) {
                return true;
            }
        }
        return false;
    }

    /** Every concrete permission the UI may ask about, evaluated for one role. @return list<string> */
    public static function granted(string $role): array
    {
        $all = [];
        foreach (self::cfg()['roles'] as $r) {
            foreach ($r['permissions'] as $p) {
                if ($p !== '*' && !str_ends_with($p, '.*')) $all[$p] = true;
            }
        }
        foreach (['inventory', 'registry', 'discovery', 'workstations', 'collectors', 'governance', 'iso', 'adoption', 'users', 'tenants', 'integrations'] as $a) {
            foreach (['read', 'write', 'delete'] as $x) $all["$a.$x"] = true;
        }
        foreach (['monitoring.write', 'retention.write', 'audit.read', 'reports.read', 'dashboard.read', 'settings.auth'] as $p) $all[$p] = true;
        return array_values(array_filter(array_keys($all), static fn ($p) => self::can($role, $p)));
    }
}
