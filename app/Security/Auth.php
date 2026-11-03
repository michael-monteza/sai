<?php
declare(strict_types=1);

namespace Saip\Security;

use Psr\Http\Message\ServerRequestInterface;
use Saip\{ApiException, Audit, Db, RateLimiter};

/** Console sign-in: sessions, lockout, password policy, tenant scoping. */
final class Auth
{
    public static function isHttps(ServerRequestInterface $r): bool
    {
        $h = $r->getServerParams()['HTTPS'] ?? '';
        return $h !== '' && $h !== 'off';
    }

    /** Origin (or Referer) of an unsafe request must match the host it was sent to. Absent headers are allowed (non-browser clients still need the token). */
    public static function sameOrigin(ServerRequestInterface $r): bool
    {
        $origin = $r->getHeaderLine('Origin');
        $src = $origin !== '' ? $origin : $r->getHeaderLine('Referer');
        if ($src === '') return true;
        $p = parse_url($src);
        if (!$p || empty($p['host'])) return false;
        $host = $p['host'] . (isset($p['port']) ? ':' . $p['port'] : '');
        return strcasecmp($host, $r->getUri()->getHost() . ($r->getUri()->getPort() ? ':' . $r->getUri()->getPort() : '')) === 0
            || strcasecmp($host, $r->getHeaderLine('Host')) === 0;
    }

    /** Session hardening: __Host- cookie over HTTPS, HttpOnly, SameSite=Strict, strict mode, idle + absolute timeouts. */
    public static function startSession(bool $https): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) return;
        session_name($https ? '__Host-saip_sid' : 'saip_sid');
        session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'httponly' => true, 'samesite' => 'Strict', 'secure' => $https]);
        ini_set('session.use_strict_mode', '1');
        ini_set('session.use_only_cookies', '1');
        session_start();
        $now = time();
        $idle = (int)Rbac::setting('idle_timeout_minutes', 480) * 60;
        $abs = (int)Rbac::setting('absolute_timeout_hours', 12) * 3600;
        if ((isset($_SESSION['last']) && $now - $_SESSION['last'] > $idle) || (isset($_SESSION['born']) && $now - $_SESSION['born'] > $abs)) {
            self::logout();
            session_start();
        }
        $_SESSION['last'] = $now;
        $_SESSION['born'] ??= $now;
    }

    /** Argon2id where available, bcrypt otherwise. */
    public static function hashPassword(string $pw): string
    {
        return password_hash($pw, defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT);
    }

    /** @return array<string,mixed>|null the signed-in, active user */
    public static function user(): ?array
    {
        $id = $_SESSION['uid'] ?? null;
        $u = $id ? Db::one('SELECT id, tenant_id, username, display_name, email, role, password_changed_at FROM admin_users WHERE id = ? AND active = 1', [$id]) : null;
        // A password change or reset ends every session created before it.
        if ($u && $u['password_changed_at'] && ($_SESSION['born'] ?? 0) < strtotime($u['password_changed_at'] . ' UTC')) {
            self::logout();
            return null;
        }
        return $u;
    }

    public static function csrf(): string { return $_SESSION['csrf'] ?? ''; }

    /** @throws ApiException on lockout / rate limit. Returns the user row on success, null on bad credentials. */
    public static function login(string $username, string $password, string $ip): ?array
    {
        RateLimiter::hit('login:' . $ip, 10);
        $u = Db::one('SELECT * FROM admin_users WHERE username = ? AND active = 1', [$username]);
        if ($u && $u['locked_until'] && strtotime($u['locked_until'] . ' UTC') > time()) {
            Audit::log($username, 'login_blocked', null, ['reason' => 'locked'], $u['tenant_id'] !== null ? (int)$u['tenant_id'] : null);
            throw new ApiException(423, 'account_locked', 'This account is temporarily locked after repeated failed sign-ins. Try again later.');
        }
        $hash = $u['password_hash'] ?? '$2y$10$usesomesillystringfore7hnbRJHxXVLeakoG8K30oukPsA.ztMG';   // constant-ish time
        if (!password_verify($password, $hash) || !$u) {
            if ($u) {
                $max = (int)Rbac::setting('max_failed_logins', 5);
                $n = (int)$u['failed_logins'] + 1;
                Db::run('UPDATE admin_users SET failed_logins = ?, locked_until = IF(? >= ?, UTC_TIMESTAMP() + INTERVAL ? MINUTE, locked_until) WHERE id = ?',
                    [$n, $n, $max, (int)Rbac::setting('lockout_minutes', 15), $u['id']]);
            }
            Audit::log($username, 'login_failed', null, null, $u && $u['tenant_id'] !== null ? (int)$u['tenant_id'] : null);
            return null;
        }
        if (password_needs_rehash($u['password_hash'], defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT)) {
            Db::run('UPDATE admin_users SET password_hash = ? WHERE id = ?', [self::hashPassword($password), $u['id']]);
        }
        if (!(int)$u['local_login']) {   // this account may only sign in with Google
            Audit::log($u['username'], 'login_failed', null, ['reason' => 'password sign-in disabled'], $u['tenant_id'] !== null ? (int)$u['tenant_id'] : null);
            return null;
        }
        self::establish($u, $ip, 'password');
        return $u;
    }

    /** Starts the authenticated session for a verified user (password or Google). */
    public static function establish(array $u, string $ip, string $method): void
    {
        session_regenerate_id(true);          // fixation defence
        $_SESSION['born'] = time();
        $_SESSION['uid'] = (int)$u['id'];
        $_SESSION['csrf'] = bin2hex(random_bytes(24));
        $_SESSION['tenant_id'] = $u['tenant_id'] !== null ? (int)$u['tenant_id'] : (int)(Db::val("SELECT id FROM tenants WHERE status = 'active' ORDER BY id LIMIT 1") ?? 0);
        Db::run('UPDATE admin_users SET last_login = UTC_TIMESTAMP(), last_login_ip = ?, failed_logins = 0, locked_until = NULL WHERE id = ?', [$ip, $u['id']]);
        Audit::log($u['username'], $method === 'google' ? 'login_google' : 'login', null, ['role' => $u['role'], 'method' => $method], $u['tenant_id'] !== null ? (int)$u['tenant_id'] : null);
    }

    public static function logout(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            $_SESSION = [];
            session_destroy();
        }
    }

    public static function tenantId(array $u): int
    {
        $tid = $u['role'] === 'super_admin' ? (int)($_SESSION['tenant_id'] ?? 0) : (int)$u['tenant_id'];
        if ($tid <= 0 || !Db::val("SELECT 1 FROM tenants WHERE id = ? AND status = 'active'", [$tid])) {
            throw new ApiException(409, 'no_tenant', 'No active company is selected. Create one under Companies.');
        }
        return $tid;
    }

    public static function switchTenant(int $tenantId): void
    {
        if (!Db::val('SELECT 1 FROM tenants WHERE id = ?', [$tenantId])) throw new ApiException(404, 'not_found', 'Unknown company.');
        $_SESSION['tenant_id'] = $tenantId;
    }

    /** Throws 422 unless the password meets policy. */
    public static function checkPassword(string $pw, string $username = ''): void
    {
        $min = (int)Rbac::setting('password_min_length', 12);
        if (strlen($pw) < $min) throw new ApiException(422, 'validation_failed', "Password must be at least $min characters.", ['password' => 'too short']);
        if ($username !== '' && stripos($pw, $username) !== false) throw new ApiException(422, 'validation_failed', 'Password must not contain the username.', ['password' => 'weak']);
        if (count(array_filter([preg_match('/[a-z]/', $pw), preg_match('/[A-Z]/', $pw), preg_match('/\d/', $pw), preg_match('/[^A-Za-z0-9]/', $pw)])) < 3) {
            throw new ApiException(422, 'validation_failed', 'Use at least three of: lowercase, uppercase, digits, symbols.', ['password' => 'weak']);
        }
    }
}
