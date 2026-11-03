<?php
declare(strict_types=1);

namespace Saip;

use PDO;

/**
 * Helpers for install.php (the web installer / upgrader). Deliberately self-contained: it is loaded before Composer's autoloader
 * is known to exist, so it must not use any other Saip class.
 */
final class Installer
{
    public const MIN_PHP = '8.2.0';
    private const MODE = 'STRICT_ALL_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';

    public static function root(): string { return dirname(__DIR__); }
    public static function version(): string { $f = self::root() . '/VERSION'; return is_file($f) ? trim((string)file_get_contents($f)) : '0.0.0'; }
    public static function lockFile(): string { return self::root() . '/config/installed.lock'; }
    public static function installed(): bool { return is_file(self::lockFile()); }

    /** @return array<string,mixed> */
    public static function lock(): array
    {
        $j = is_file(self::lockFile()) ? json_decode((string)file_get_contents(self::lockFile()), true) : null;
        return is_array($j) ? $j : [];
    }

    public static function writeLock(array $data): void
    {
        self::atomic(self::lockFile(), json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n", 0640);
    }

    public static function atomic(string $file, string $content, int $mode): void
    {
        $tmp = $file . '.tmp' . bin2hex(random_bytes(3));
        if (file_put_contents($tmp, $content) === false) throw new \RuntimeException("Cannot write $file (check folder permissions).");
        @chmod($tmp, $mode);
        if (!@rename($tmp, $file)) { @unlink($tmp); throw new \RuntimeException("Cannot replace $file."); }
    }

    /** @return list<array{label:string,ok:bool,detail:string,required:bool}> */
    public static function requirements(): array
    {
        $r = [];
        $add = static function (string $label, bool $ok, string $detail, bool $required = true) use (&$r): void { $r[] = compact('label', 'ok', 'detail', 'required'); };
        $add('PHP ' . self::MIN_PHP . ' or newer', version_compare(PHP_VERSION, self::MIN_PHP, '>='), 'running ' . PHP_VERSION);
        foreach (['pdo_mysql' => 'database driver', 'sodium' => 'encrypts stored secrets', 'mbstring' => 'text handling', 'openssl' => 'TLS / Google sign-in', 'curl' => 'SIEM, webhooks and Google', 'json' => 'JSON'] as $ext => $why) {
            $add("PHP extension $ext", extension_loaded($ext), $why, $ext !== 'curl');
        }
        $add('Composer packages (vendor/)', is_file(self::root() . '/vendor/autoload.php'), 'run "composer install --no-dev" if missing');
        $conf = self::root() . '/config';
        $add('config/ folder is writable', is_dir($conf) && is_writable($conf), 'the installer writes config.php, app.key and installed.lock there');
        $add('sql/ files present', is_file(self::root() . '/sql/schema.sql') && is_dir(self::root() . '/sql/migrations'), 'database definition');
        $add('Apache mod_rewrite', !function_exists('apache_get_modules') || in_array('mod_rewrite', apache_get_modules(), true), 'needed for clean URLs (.htaccess); cannot be checked under some PHP handlers', false);
        return $r;
    }

    public static function requirementsMet(): bool
    {
        foreach (self::requirements() as $q) if ($q['required'] && !$q['ok']) return false;
        return true;
    }

    public static function siteUrl(): string
    {
        $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (($_SERVER['SERVER_PORT'] ?? '') === '443');
        $dir = str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/'));
        return ($https ? 'https' : 'http') . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost') . ($dir === '/' || $dir === '.' ? '' : rtrim($dir, '/'));
    }

    public static function validName(string $s): bool { return (bool)preg_match('/^[A-Za-z0-9_]{1,64}$/', $s); }
    public static function validHost(string $s): bool { return (bool)preg_match('/^[A-Za-z0-9_.%:\-]{1,100}$/', $s); }

    public static function connect(string $host, int $port, string $user, string $pass, ?string $db = null, ?string $ca = null): PDO
    {
        $dsn = "mysql:host=$host;port=$port;" . ($db !== null ? "dbname=$db;" : '') . 'charset=utf8mb4';
        $opt = [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES => true, PDO::ATTR_TIMEOUT => 8];
        if ($ca) { $opt[PDO::MYSQL_ATTR_SSL_CA] = $ca; $opt[PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] = true; }
        $pdo = new PDO($dsn, $user, $pass, $opt);
        $pdo->exec("SET time_zone = '+00:00', SESSION sql_mode = '" . self::MODE . "'");
        return $pdo;
    }

    /** @return list<string> */
    public static function tables(PDO $pdo): array
    {
        return array_column($pdo->query('SELECT TABLE_NAME t FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = "BASE TABLE"')->fetchAll(), 't');
    }

    /** Describes what is already in the database: nothing, an unrelated schema, or an earlier SAIP install. */
    public static function inspect(PDO $pdo): array
    {
        $t = self::tables($pdo);
        $saip = in_array('tenants', $t, true) && in_array('collectors', $t, true);
        $out = ['tables' => count($t), 'saip' => $saip, 'companies' => 0, 'users' => 0, 'events' => 0, 'applied' => [], 'pending' => array_map(static fn ($f) => basename($f, '.up.sql'), self::migrationFiles())];
        if ($saip) {
            $out['companies'] = (int)$pdo->query('SELECT COUNT(*) FROM tenants')->fetchColumn();
            $out['users'] = in_array('admin_users', $t, true) ? (int)$pdo->query('SELECT COUNT(*) FROM admin_users')->fetchColumn() : 0;
            $out['events'] = in_array('ai_usage_events', $t, true) ? (int)$pdo->query('SELECT COUNT(*) FROM ai_usage_events')->fetchColumn() : 0;
            if (in_array('schema_migrations', $t, true)) {
                $out['applied'] = array_column($pdo->query('SELECT name FROM schema_migrations ORDER BY name')->fetchAll(), 'name');
                $out['pending'] = array_values(array_diff($out['pending'], $out['applied']));
            }
        }
        return $out;
    }

    /** @return list<string> */
    public static function migrationFiles(): array
    {
        $f = glob(self::root() . '/sql/migrations/*.up.sql') ?: [];
        sort($f);
        return $f;
    }

    /** Runs a .sql file: statements end with ";" at end of line; comments, CREATE DATABASE and USE lines are skipped (the database is chosen by the connection). */
    public static function runSql(PDO $pdo, string $file): void
    {
        $buf = '';
        foreach (preg_split('/\R/', (string)file_get_contents($file)) as $line) {
            if (str_starts_with(ltrim($line), '--') || preg_match('/^\s*(CREATE\s+DATABASE|USE)\s/i', $line)) continue;
            $buf .= $line . "\n";
            if (preg_match('/;\s*$/', $line)) { $pdo->exec($buf); $buf = ''; }
        }
        if (trim($buf) !== '') $pdo->exec($buf);
    }

    /** Applies every migration not yet recorded. Returns the names applied. @return list<string> */
    public static function migrate(PDO $pdo): array
    {
        $pdo->exec('CREATE TABLE IF NOT EXISTS schema_migrations (name VARCHAR(100) NOT NULL PRIMARY KEY, applied_at DATETIME NOT NULL DEFAULT UTC_TIMESTAMP()) ENGINE=InnoDB');
        $done = array_column($pdo->query('SELECT name FROM schema_migrations')->fetchAll(), 'name');
        $applied = [];
        foreach (self::migrationFiles() as $file) {
            $name = basename($file, '.up.sql');
            if (in_array($name, $done, true)) continue;
            self::runSql($pdo, $file);
            $pdo->prepare('INSERT INTO schema_migrations (name) VALUES (?)')->execute([$name]);
            $applied[] = $name;
        }
        return $applied;
    }

    public static function dropAll(PDO $pdo): int
    {
        $t = self::tables($pdo);
        $pdo->exec('SET FOREIGN_KEY_CHECKS = 0');
        foreach ($t as $name) $pdo->exec('DROP TABLE IF EXISTS `' . str_replace('`', '``', $name) . '`');
        $pdo->exec('SET FOREIGN_KEY_CHECKS = 1');
        return count($t);
    }

    /** @return list<string> account hosts to create/grant for the application account */
    public static function accountHosts(string $allowedFrom): array
    {
        return in_array(strtolower($allowedFrom), ['localhost', '127.0.0.1'], true) ? ['localhost', '127.0.0.1'] : [$allowedFrom];
    }

    public static function createDatabaseAndUser(PDO $admin, string $db, string $user, string $pass, array $hosts): void
    {
        $admin->exec('CREATE DATABASE IF NOT EXISTS `' . $db . '` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');
        foreach ($hosts as $h) {
            $acct = $admin->quote($user) . '@' . $admin->quote($h);
            $admin->exec("CREATE USER IF NOT EXISTS $acct IDENTIFIED BY " . $admin->quote($pass));
            $admin->exec("ALTER USER $acct IDENTIFIED BY " . $admin->quote($pass));
        }
    }

    /** Least privilege: data access per table, the audit trail append-only, no schema changes. Re-run after an upgrade that adds tables. */
    public static function grantLeastPrivilege(PDO $admin, string $db, string $user, array $hosts): int
    {
        $tables = self::tables($admin);
        foreach ($hosts as $h) {
            $acct = $admin->quote($user) . '@' . $admin->quote($h);
            foreach ($tables as $t) {
                $priv = $t === 'audit_logs' ? 'SELECT, INSERT' : ($t === 'schema_migrations' ? 'SELECT' : 'SELECT, INSERT, UPDATE, DELETE');
                try { $admin->exec("REVOKE ALL PRIVILEGES ON `$db`.`$t` FROM $acct"); } catch (\Throwable) { /* nothing granted yet */ }
                $admin->exec("GRANT $priv ON `$db`.`$t` TO $acct");
            }
        }
        $admin->exec('FLUSH PRIVILEGES');
        return count($tables);
    }

    public static function writeConfig(array $c): void
    {
        $php = "<?php\n// Written by install.php on " . gmdate('Y-m-d H:i') . " UTC. Edit with care; never commit this file (it holds the database password).\nreturn " . var_export($c, true) . ";\n";
        self::atomic(self::root() . '/config/config.php', $php, 0640);
    }

    public static function randomPassword(int $len = 24): string
    {
        $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_.';
        $out = '';
        for ($i = 0; $i < $len; $i++) $out .= $chars[random_int(0, strlen($chars) - 1)];
        return $out;
    }

    public static function newAppKey(): void
    {
        self::atomic(self::root() . '/config/app.key', base64_encode(random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES)), 0600);
    }

    /** Plain-language reason for common database connection failures. */
    public static function explain(\Throwable $e): string
    {
        $m = $e->getMessage();
        return match (true) {
            str_contains($m, '1045') => 'Access denied: wrong database user or password.',
            str_contains($m, '1049') => 'That database does not exist.',
            str_contains($m, '2002'), str_contains($m, 'getaddrinfo') => 'Cannot reach the database server: check host and port.',
            str_contains($m, '1044') => 'This account has no permission on that database.',
            str_contains($m, '1227'), str_contains($m, '1142') => 'This account is not allowed to do that: use an administrative database account.',
            default => preg_replace('/\s+/', ' ', $m) ?? $m,
        };
    }
}
