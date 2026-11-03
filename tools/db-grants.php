<?php
declare(strict_types=1);

/**
 * Grants the least-privilege runtime account per-table data access, with the audit trail append-only.
 *   php tools/db-grants.php saip_app [host=localhost]
 * Run with an administrative database account (SAIP_DB_USER/SAIP_DB_PASS). Re-run after adding tables.
 */
require __DIR__ . '/../app/bootstrap.php';

use Saip\Db;

if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
$user = $argv[1] ?? '';
$host = $argv[2] ?? 'localhost';
if (!preg_match('/^[A-Za-z0-9_]{1,32}$/', $user) || !preg_match('/^[A-Za-z0-9_.%-]{1,60}$/', $host)) { fwrite(STDERR, "Usage: php tools/db-grants.php <account> [host]\n"); exit(2); }
$db = Saip\Config::get('db.name');
$acct = "'$user'@'$host'";
foreach (Db::all('SELECT TABLE_NAME t FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = "BASE TABLE"') as $r) {
    $t = $r['t'];
    try { Db::pdo()->exec("REVOKE ALL PRIVILEGES ON `$db`.`$t` FROM $acct"); } catch (\Throwable) { /* nothing granted yet */ }
    $priv = $t === 'audit_logs' ? 'SELECT, INSERT' : ($t === 'schema_migrations' ? 'SELECT' : 'SELECT, INSERT, UPDATE, DELETE');
    Db::pdo()->exec("GRANT $priv ON `$db`.`$t` TO $acct");
    echo str_pad($t, 32) . $priv . "\n";
}
Db::pdo()->exec('FLUSH PRIVILEGES');
echo "Done. The account can no longer alter or delete audit_logs, or change the schema.\n";
