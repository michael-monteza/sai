<?php
declare(strict_types=1);

namespace Saip\Modules;

use Psr\Http\Message\{ResponseInterface as Response, ServerRequestInterface as Request};
use Saip\{ApiException, Audit, Db, HttpClient, PlatformSettings};
use Saip\Http\Controller;
use Saip\Middleware\RequirePermission as Need;
use Saip\Security\GoogleAuth;
use Slim\Routing\RouteCollectorProxy as Group;

/** Platform authentication settings (Google Sign-In). Platform administrators only: they affect every company. */
final class SettingsModule extends Controller
{
    public static function register(Group $g): void
    {
        $g->get('/settings/auth', [self::class, 'authGet'])->add(new Need('settings.auth'));
        $g->post('/settings/auth', [self::class, 'authSave'])->add(new Need('settings.auth'));
        $g->post('/settings/auth/test', [self::class, 'authTest'])->add(new Need('settings.auth'));
    }

    private function view(Request $req): array
    {
        return ['google' => [
            'enabled' => PlatformSettings::get('google.enabled') === '1',
            'client_id' => PlatformSettings::get('google.client_id', ''),
            'has_secret' => PlatformSettings::has('google.client_secret'),
            'allowed_domains' => PlatformSettings::get('google.allowed_domains', ''),
            'auto_provision' => PlatformSettings::get('google.auto_provision') === '1',
            'default_role' => PlatformSettings::get('google.default_role', 'viewer'),
            'default_tenant_id' => (int)PlatformSettings::get('google.default_tenant_id', '0'),
            'redirect_override' => PlatformSettings::get('google.redirect_uri', ''),
            'redirect_uri' => GoogleAuth::redirectUri($req),
        ], 'tenants' => Db::all("SELECT id, name FROM tenants WHERE status = 'active' ORDER BY name"),
           'google_users' => (int)Db::val('SELECT COUNT(*) FROM admin_users WHERE google_sub IS NOT NULL')];
    }

    public function authGet(Request $req, Response $res): Response { return $this->json($res, $this->view($req)); }

    public function authSave(Request $req, Response $res): Response
    {
        $b = $this->body($req)['google'] ?? null;
        if (!is_array($b)) throw new ApiException(422, 'validation_failed', '"google" settings are required.');
        $before = $this->view($req)['google'];
        $clientId = trim((string)($b['client_id'] ?? ''));
        if ($clientId !== '' && !preg_match('/^[A-Za-z0-9._-]{10,200}$/', $clientId)) throw new ApiException(422, 'validation_failed', 'The client id looks invalid.', ['client_id' => 'invalid']);
        $domains = array_values(array_unique(array_filter(array_map(static fn ($d) => strtolower(trim($d)), explode(',', (string)($b['allowed_domains'] ?? ''))))));
        foreach ($domains as $d) if (!preg_match('/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/', $d)) throw new ApiException(422, 'validation_failed', "Invalid domain: $d", ['allowed_domains' => 'invalid']);
        $role = (string)($b['default_role'] ?? 'viewer');
        if (!in_array($role, ['viewer', 'auditor', 'it_admin'], true)) throw new ApiException(422, 'validation_failed', 'Invalid default role.', ['default_role' => 'invalid']);
        $auto = !empty($b['auto_provision']);
        $tenant = (int)($b['default_tenant_id'] ?? 0);
        if ($auto && (!$domains || !Db::val("SELECT 1 FROM tenants WHERE id = ? AND status = 'active'", [$tenant]))) {
            throw new ApiException(422, 'validation_failed', 'Automatic account creation needs at least one allowed domain and a default company.', ['auto_provision' => 'incomplete']);
        }
        $redirect = trim((string)($b['redirect_override'] ?? ''));
        if ($redirect !== '' && !preg_match('#^https?://[^\s]+/auth/google/callback$#', $redirect)) throw new ApiException(422, 'validation_failed', 'The redirect URI must end with /auth/google/callback.', ['redirect_override' => 'invalid']);
        $secret = (string)($b['client_secret'] ?? '');
        $enable = !empty($b['enabled']);
        if ($enable && ($clientId === '' || ($secret === '' && !PlatformSettings::has('google.client_secret')))) throw new ApiException(422, 'validation_failed', 'A client id and client secret are required to enable Google sign-in.', ['enabled' => 'incomplete']);

        $u = $this->actor($req);
        PlatformSettings::set('google.client_id', $clientId, $u);
        if ($secret !== '') PlatformSettings::set('google.client_secret', $secret, $u, true);
        elseif (!empty($b['clear_secret'])) PlatformSettings::set('google.client_secret', null, $u, true);
        PlatformSettings::set('google.allowed_domains', implode(',', $domains), $u);
        PlatformSettings::set('google.auto_provision', $auto ? '1' : '0', $u);
        PlatformSettings::set('google.default_role', $role, $u);
        PlatformSettings::set('google.default_tenant_id', (string)$tenant, $u);
        PlatformSettings::set('google.redirect_uri', $redirect, $u);
        PlatformSettings::set('google.enabled', $enable ? '1' : '0', $u);
        $after = $this->view($req)['google'];
        Audit::log($u, 'auth_settings_changed', 'google', ['secret_changed' => $secret !== ''], null, $before, $after);   // the secret itself is never logged
        return $this->json($res, $this->view($req));
    }

    /** Checks that Google's discovery document is reachable and that the stored client id is plausible. */
    public function authTest(Request $req, Response $res): Response
    {
        $r = HttpClient::request('GET', 'https://accounts.google.com/.well-known/openid-configuration', ['Accept' => 'application/json'], null, 8);
        $doc = json_decode($r['body'], true);
        $cid = (string)PlatformSettings::get('google.client_id', '');
        return $this->json($res, ['reachable' => $r['status'] === 200 && isset($doc['authorization_endpoint']), 'client_id_set' => $cid !== '', 'client_id_format' => (bool)preg_match('/\.apps\.googleusercontent\.com$/', $cid),
            'secret_set' => PlatformSettings::has('google.client_secret'), 'redirect_uri' => GoogleAuth::redirectUri($req), 'error' => $r['error']]);
    }
}
