<?php
// php tools\create-admin.php <username> <password> <super_admin|it_admin|viewer> [tenant-slug]
// super_admin has no tenant (platform owner). it_admin / viewer require the company slug.
declare(strict_types=1);
if (PHP_SAPI !== 'cli') exit(1);
require __DIR__ . '/../app/bootstrap.php';

use Saip\{Audit, Db};

[, $user, $pass, $role, $slug] = $argv + [null, null, null, null, null];
if (!$user || !$pass || !in_array($role, ['super_admin', 'it_admin', 'auditor', 'viewer'], true)) {
    fwrite(STDERR, "Usage: create-admin.php <username> <password(12+)> <super_admin|it_admin|viewer> [tenant-slug]\n");
    exit(2);
}
if (strlen($pass) < 12) { fwrite(STDERR, "Password must be at least 12 characters.\n"); exit(2); }
$tid = null;
if ($role !== 'super_admin') {
    $tid = Db::val('SELECT id FROM tenants WHERE slug = ?', [$slug ?? '']);
    if (!$tid) { fwrite(STDERR, "Tenant slug required and must exist.\n"); exit(2); }
}
Saip\Security\Auth::checkPassword($pass, $user);
Db::run('INSERT INTO admin_users (tenant_id, username, display_name, password_hash, role, password_changed_at) VALUES (?,?,?,?,?,UTC_TIMESTAMP())',
    [$tid, $user, $user, Saip\Security\Auth::hashPassword($pass), $role]);
Audit::log('cli:' . (getenv('USERNAME') ?: 'admin'), 'user_created', $user, ['role' => $role], $tid ? (int)$tid : null);
echo "Created $role '$user'" . ($tid ? " for tenant $slug" : '') . ".\n";
