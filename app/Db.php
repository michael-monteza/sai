<?php
declare(strict_types=1);

namespace Saip;

use PDO;

final class Db
{
    private static ?PDO $pdo = null;

    public static function pdo(): PDO
    {
        if (self::$pdo === null) {
            $dsn = sprintf(
                'mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4',
                Config::get('db.host'), Config::get('db.port'), Config::get('db.name')
            );
            $opt = [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,        // real server-side prepared statements: no SQL injection via emulation quirks
                PDO::ATTR_STRINGIFY_FETCHES  => false,
            ];
            if ($ca = Config::get('db.ssl_ca')) {              // TLS to a remote database server (OWASP A02)
                $opt[PDO::MYSQL_ATTR_SSL_CA] = $ca;
                $opt[PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] = true;
            }
            self::$pdo = new PDO($dsn, (string)Config::get('db.user'), (string)Config::get('db.password'), $opt);
            self::$pdo->exec("SET time_zone = '+00:00', SESSION sql_mode = 'STRICT_ALL_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION'");
        }
        return self::$pdo;
    }

    /** @return list<array<string,mixed>> */
    public static function all(string $sql, array $args = []): array
    {
        $st = self::pdo()->prepare($sql);
        $st->execute($args);
        return $st->fetchAll();
    }

    public static function one(string $sql, array $args = []): ?array
    {
        $st = self::pdo()->prepare($sql);
        $st->execute($args);
        $r = $st->fetch();
        return $r === false ? null : $r;
    }

    public static function val(string $sql, array $args = []): mixed
    {
        $st = self::pdo()->prepare($sql);
        $st->execute($args);
        $v = $st->fetchColumn();
        return $v === false ? null : $v;
    }

    /** Executes a write; returns affected rows. */
    public static function run(string $sql, array $args = []): int
    {
        $st = self::pdo()->prepare($sql);
        $st->execute($args);
        return $st->rowCount();
    }

    public static function insertId(): int
    {
        return (int)self::pdo()->lastInsertId();
    }
}
