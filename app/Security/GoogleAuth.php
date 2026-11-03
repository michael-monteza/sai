<?php
declare(strict_types=1);

namespace Saip\Security;

use Psr\Http\Message\ServerRequestInterface;
use Saip\{ApiException, Audit, Config, Db, HttpClient, PlatformSettings};

/**
 * Google Sign-In with OpenID Connect (authorization-code flow + PKCE, state and nonce).
 * The ID token is received straight from Google's token endpoint over TLS (OIDC Core 3.1.3.7), then issuer, audience, expiry, nonce,
 * verified email and the optional Workspace-domain restriction are checked. Accounts must already exist (matched by Google subject, then by
 * verified email) unless auto-provisioning is switched on. Passwords keep working ("sign in internally") unless a user is set to Google-only.
 */
final class GoogleAuth
{
    private const AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
    private const TOKEN_URL = 'https://oauth2.googleapis.com/token';

    public static function enabled(): bool
    {
        return PlatformSettings::get('google.enabled') === '1' && PlatformSettings::has('google.client_id') && PlatformSettings::has('google.client_secret');
    }

    /** The redirect URI to register in Google Cloud Console. */
    public static function redirectUri(ServerRequestInterface $r): string
    {
        if ($o = PlatformSettings::get('google.redirect_uri')) return $o;
        if ($b = Config::get('base_url')) return rtrim((string)$b, '/') . '/auth/google/callback';
        $u = $r->getUri();
        $base = rtrim(\Slim\Routing\RouteContext::fromRequest($r)->getBasePath(), '/');
        $port = $u->getPort();
        return $u->getScheme() . '://' . $u->getHost() . ($port && !in_array($port, [80, 443], true) ? ":$port" : '') . $base . '/auth/google/callback';
    }

    private static function b64u(string $s): string { return rtrim(strtr(base64_encode($s), '+/', '-_'), '='); }

    public const COOKIE = 'saip_oauth';

    public static function cookieName(ServerRequestInterface $r): string { return Auth::isHttps($r) ? '__Host-' . self::COOKIE : self::COOKIE; }

    /**
     * Starts the flow. The state, nonce and PKCE verifier travel in a short-lived encrypted cookie (HttpOnly, SameSite=Lax) instead of the session:
     * the console session cookie is SameSite=Strict, so the browser does not send it when Google redirects back to us.
     * @return array{0:string,1:string} [Google URL, cookie value]
     */
    public static function start(ServerRequestInterface $r): array
    {
        if (!self::enabled()) throw new ApiException(404, 'not_found', 'Google sign-in is not enabled.');
        $state = bin2hex(random_bytes(16)); $nonce = bin2hex(random_bytes(16)); $verifier = self::b64u(random_bytes(48));
        $q = [
            'client_id' => PlatformSettings::get('google.client_id'), 'redirect_uri' => self::redirectUri($r), 'response_type' => 'code', 'scope' => 'openid email profile',
            'state' => $state, 'nonce' => $nonce, 'code_challenge' => self::b64u(hash('sha256', $verifier, true)), 'code_challenge_method' => 'S256',
            'prompt' => 'select_account',
        ];
        $domains = self::domains();
        if (count($domains) === 1) $q['hd'] = $domains[0];
        return [self::AUTH_URL . '?' . http_build_query($q), Secrets::encrypt(json_encode(['s' => $state, 'n' => $nonce, 'v' => $verifier, 'e' => time() + 600]))];
    }

    /** @return list<string> */
    private static function domains(): array
    {
        return array_values(array_filter(array_map(static fn ($d) => strtolower(trim($d)), explode(',', (string)PlatformSettings::get('google.allowed_domains', '')))));
    }

    /**
     * Completes the flow and returns the matching (or provisioned) admin_users row.
     * @throws ApiException with a safe, user-readable message on any failure
     */
    public static function finish(ServerRequestInterface $r, string $code, string $state): array
    {
        $ip = (string)$r->getAttribute('client_ip');
        $fail = static function (string $msg, string $why, ?string $email = null) use ($ip): never {
            Audit::log($email ?? 'google', 'login_google_failed', null, ['reason' => $why, 'ip' => $ip]);
            throw new ApiException(403, 'google_denied', $msg, ['why' => $why]);
        };
        if (!self::enabled()) throw new ApiException(404, 'not_found', 'Google sign-in is not enabled.');
        $flow = json_decode((string)Secrets::decrypt($r->getCookieParams()[self::cookieName($r)] ?? null), true);
        $expect = is_array($flow) && ($flow['e'] ?? 0) >= time() ? (string)($flow['s'] ?? '') : ''; $nonce = (string)($flow['n'] ?? ''); $verifier = (string)($flow['v'] ?? '');
        if ($expect === '') $fail('The Google sign-in session expired or the browser blocked its cookie. Please try again from the login page, using the same address you used to open it.', 'flow cookie missing or expired');
        if (!hash_equals($expect, $state) || $code === '') $fail('The Google sign-in session expired. Please try again.', 'state mismatch');

        $res = HttpClient::request('POST', self::TOKEN_URL, ['Content-Type' => 'application/x-www-form-urlencoded', 'Accept' => 'application/json'], http_build_query([
            'code' => $code, 'client_id' => PlatformSettings::get('google.client_id'), 'client_secret' => PlatformSettings::get('google.client_secret'),
            'redirect_uri' => self::redirectUri($r), 'grant_type' => 'authorization_code', 'code_verifier' => $verifier]), 10, false);
        $tok = json_decode($res['body'], true);
        if ($res['status'] !== 200 || !is_array($tok) || empty($tok['id_token'])) $fail('Google did not accept the sign-in. Please try again.', 'token exchange ' . $res['status']);

        $parts = explode('.', (string)$tok['id_token']);
        $claims = count($parts) === 3 ? json_decode((string)base64_decode(strtr($parts[1], '-_', '+/')), true) : null;
        if (!is_array($claims)) $fail('Google returned an unreadable identity token.', 'bad id_token');
        $email = strtolower((string)($claims['email'] ?? ''));
        if (!in_array($claims['iss'] ?? '', ['https://accounts.google.com', 'accounts.google.com'], true) || ($claims['aud'] ?? '') !== PlatformSettings::get('google.client_id')
            || (int)($claims['exp'] ?? 0) < time() - 60 || !hash_equals($nonce, (string)($claims['nonce'] ?? '')) || empty($claims['sub'])) $fail('The Google identity token could not be verified.', 'claims invalid', $email ?: null);
        if (empty($claims['email_verified']) || $email === '') $fail('Your Google account email is not verified.', 'email not verified', $email ?: null);
        $domains = self::domains();
        $domain = substr(strrchr($email, '@') ?: '', 1);
        if ($domains && (!in_array($domain, $domains, true) || (isset($claims['hd']) && !in_array(strtolower((string)$claims['hd']), $domains, true) && !in_array($domain, $domains, true)))) {
            $fail('This Google account is not from an allowed domain.', 'domain not allowed', $email);
        }

        $sub = (string)$claims['sub'];
        $u = Db::one('SELECT * FROM admin_users WHERE google_sub = ?', [$sub]) ?: Db::one('SELECT * FROM admin_users WHERE LOWER(email) = ? AND google_sub IS NULL', [$email]);
        if ($u && !$u['google_sub']) {   // first Google sign-in of an existing account: link it
            Db::run('UPDATE admin_users SET google_sub = ? WHERE id = ?', [$sub, $u['id']]);
            Audit::log($u['username'], 'google_linked', $email, null, $u['tenant_id'] !== null ? (int)$u['tenant_id'] : null);
        }
        if (!$u && PlatformSettings::get('google.auto_provision') === '1') {
            $role = (string)PlatformSettings::get('google.default_role', 'viewer');
            $tenant = (int)PlatformSettings::get('google.default_tenant_id', '0');
            if (!in_array($role, ['viewer', 'auditor', 'it_admin'], true) || !Db::val("SELECT 1 FROM tenants WHERE id = ? AND status = 'active'", [$tenant])) $fail('Automatic account creation is not configured correctly. Contact an administrator.', 'provision misconfigured', $email);
            $base = preg_replace('/[^A-Za-z0-9._@-]/', '', $email) ?: 'google-user';
            $username = $base; $n = 1;
            while (Db::val('SELECT 1 FROM admin_users WHERE username = ?', [$username])) $username = $base . '-' . (++$n);
            Db::run('INSERT INTO admin_users (tenant_id, username, display_name, email, password_hash, role, google_sub, local_login, password_changed_at) VALUES (?,?,?,?,?,?,?,0,UTC_TIMESTAMP())',
                [$tenant, $username, mb_substr((string)($claims['name'] ?? $username), 0, 100), $email, Auth::hashPassword(bin2hex(random_bytes(24)) . 'Aa1!'), $role, $sub]);
            Audit::log('google', 'user_provisioned', $username, ['email' => $email, 'role' => $role], $tenant);
            $u = Db::one('SELECT * FROM admin_users WHERE google_sub = ?', [$sub]);
        }
        if (!$u) $fail('No console account exists for this Google address. Ask an administrator to add you.', 'no account', $email);
        if (!(int)$u['active']) $fail('This account is deactivated.', 'inactive', $email);
        return $u;
    }
}
