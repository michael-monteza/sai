<?php
declare(strict_types=1);

/**
 * Usage:
 *   php tools/migrate.php            apply all pending migrations
 *   php tools/migrate.php status     list applied / pending
 *   php tools/migrate.php down       roll back the most recent migration
 */
require __DIR__ . '/../app/bootstrap.php';

use Saip\Db;

if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }

$dir = __DIR__ . '/../sql/migrations';
$pdo = Db::pdo();
$pdo->exec('CREATE TABLE IF NOT EXISTS schema_migrations (
  name VARCHAR(100) NOT NULL PRIMARY KEY,
  applied_at DATETIME NOT NULL DEFAULT UTC_TIMESTAMP()
) ENGINE=InnoDB');

$applied = array_column(Db::all('SELECT name FROM schema_migrations ORDER BY name'), 'name');
$all = [];
foreach (glob($dir . '/*.up.sql') as $f) {
    $all[] = basename($f, '.up.sql');
}
sort($all);

function runFile(PDO $pdo, string $file): void
{
    // Statements end with ";" at end of line; comment-only lines are skipped.
    $buf = '';
    foreach (preg_split('/\R/', (string)file_get_contents($file)) as $line) {
        if (str_starts_with(ltrim($line), '--')) continue;
        $buf .= $line . "\n";
        if (preg_match('/;\s*$/', $line)) {
            $pdo->exec($buf);
            $buf = '';
        }
    }
    if (trim($buf) !== '') $pdo->exec($buf);
}

$cmd = $argv[1] ?? 'up';
if ($cmd === 'status') {
    foreach ($all as $n) echo (in_array($n, $applied, true) ? '[applied] ' : '[pending] ') . $n . "\n";
    exit(0);
}
if ($cmd === 'down') {
    $last = end($applied);
    if (!$last) { echo "Nothing to roll back.\n"; exit(0); }
    runFile($pdo, "$dir/$last.down.sql");
    Db::run('DELETE FROM schema_migrations WHERE name = ?', [$last]);
    echo "Rolled back $last\n";
    exit(0);
}
$n = 0;
foreach ($all as $name) {
    if (in_array($name, $applied, true)) continue;
    echo "Applying $name ... ";
    runFile($pdo, "$dir/$name.up.sql");
    Db::run('INSERT INTO schema_migrations (name) VALUES (?)', [$name]);
    echo "ok\n";
    $n++;
}
echo $n ? "Applied $n migration(s).\n" : "Up to date.\n";
