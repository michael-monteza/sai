<?php
// CLI administration until the Phase 4 admin UI exists.
//   php tools\collector-admin.php list
//   php tools\collector-admin.php authorize|suspend|revoke <uuid|computer_name>
//   php tools\collector-admin.php rotate <uuid|computer_name>     (prints a new API key once)
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    exit(1);
}
require __DIR__ . '/../app/bootstrap.php';

use Saip\{Audit, CollectorAuth, Db};

[, $cmd, $target] = $argv + [null, 'list', null];
$pdo = Db::pdo();
$actor = 'cli:' . (getenv('USERNAME') ?: 'admin');

if ($cmd === 'list') {
    foreach ($pdo->query('SELECT computer_name, collector_uuid, status, last_seen, collector_version FROM collectors ORDER BY computer_name') as $r) {
        printf("%-16s %-36s %-11s %-19s %s\n", $r['computer_name'], $r['collector_uuid'], $r['status'], $r['last_seen'] ?? '-', $r['collector_version']);
    }
    exit(0);
}

if (!in_array($cmd, ['authorize', 'suspend', 'revoke', 'rotate'], true) || !$target) {
    fwrite(STDERR, "Usage: collector-admin.php list | authorize|suspend|revoke|rotate <uuid|computer_name>\n");
    exit(2);
}
$st = $pdo->prepare('SELECT * FROM collectors WHERE collector_uuid = ? OR computer_name = ?');
$st->execute([strtolower($target), strtoupper($target)]);
$rows = $st->fetchAll();
if (count($rows) !== 1) {
    fwrite(STDERR, count($rows) === 0 ? "No such collector.\n" : "Ambiguous name; use the UUID.\n");
    exit(1);
}
$c = $rows[0];

if ($cmd === 'rotate') {
    $key = CollectorAuth::newApiKey();
    $pdo->prepare('UPDATE collectors SET api_key_hash = ? WHERE id = ?')->execute([CollectorAuth::hashKey($key), $c['id']]);
    Audit::log($actor, 'credential_rotated', $c['collector_uuid'], ['computer_name' => $c['computer_name']]);
    echo "New API key for {$c['computer_name']} (shown once):\n$key\n";
    exit(0);
}
$status = ['authorize' => 'authorized', 'suspend' => 'suspended', 'revoke' => 'revoked'][$cmd];
$pdo->prepare('UPDATE collectors SET status = ? WHERE id = ?')->execute([$status, $c['id']]);
Audit::log($actor, "collector_$status", $c['collector_uuid'], ['computer_name' => $c['computer_name'], 'from' => $c['status']]);
echo "{$c['computer_name']}: {$c['status']} -> $status\n";
