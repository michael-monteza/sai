<?php
declare(strict_types=1);

namespace Saip\Modules;

use Psr\Http\Message\{ResponseInterface as Response, ServerRequestInterface as Request};
use Saip\{ApiException, Audit};
use Saip\Http\Controller;
use Saip\Security\{Auth, GoogleAuth, Rbac};
use Slim\Routing\RouteCollectorProxy as Group;

/** HTML pages: console shell, sign-in, sign-out. Login and logout are CSRF-protected too (login CSRF, forced-logout CSRF). */
final class PagesModule extends Controller
{
    /** Google sign-in failures reach /login as a code (never free text), so a crafted link cannot show an arbitrary message. */
    private const GOOGLE_ERRORS = [
        'expired' => 'The Google sign-in session expired or the browser blocked its cookie. Open the login page again and use the same address as before.',
        'domain' => 'This Google account is not from an allowed domain.',
        'noaccount' => 'No console account exists for this Google address. Ask an administrator to add you, or to enable automatic account creation.',
        'inactive' => 'This account is deactivated.',
        'unverified' => 'Your Google account email is not verified.',
        'cancelled' => 'Google sign-in was cancelled.',
        'failed' => 'Google sign-in failed. Please try again or sign in with your password.',
    ];
    private const GOOGLE_WHY = ['flow cookie missing or expired' => 'expired', 'state mismatch' => 'expired', 'domain not allowed' => 'domain', 'no account' => 'noaccount', 'inactive' => 'inactive', 'email not verified' => 'unverified'];

    public static function register(Group $g): void
    {
        foreach (['/', '/index.php'] as $p) $g->get($p, [self::class, 'shell']);
        foreach (['/login', '/login.php'] as $p) {
            $g->get($p, [self::class, 'loginForm']);
            $g->post($p, [self::class, 'login']);
        }
        $g->get('/auth/google', [self::class, 'googleStart']);
        $g->get('/auth/google/callback', [self::class, 'googleCallback']);
        $g->post('/logout', [self::class, 'logout']);
        $g->get('/logout', static fn (Request $r, Response $s) => $s->withStatus(302)->withHeader('Location', self::base($r) . '/login'));
    }

    private static function base(Request $r): string
    {
        return rtrim(\Slim\Routing\RouteContext::fromRequest($r)->getBasePath(), '/');
    }

    private function view(Response $res, string $name, array $vars): Response
    {
        extract($vars, EXTR_SKIP);
        ob_start();
        require SAIP_ROOT . "/app/Views/$name.php";
        $res->getBody()->write((string)ob_get_clean());
        return $res->withHeader('Content-Type', 'text/html; charset=utf-8')->withHeader('Cache-Control', 'no-store');
    }

    private function redirect(Response $res, string $to): Response { return $res->withStatus(302)->withHeader('Location', $to); }

    public function shell(Request $req, Response $res): Response
    {
        Auth::startSession(Auth::isHttps($req));
        $u = Auth::user();
        if (!$u) return $this->redirect($res, self::base($req) . '/login');
        return $this->view($res, 'shell', ['user' => $u, 'csrf' => Auth::csrf(), 'base' => self::base($req), 'can' => static fn (string $p) => Rbac::can($u['role'], $p)]);
    }

    public function loginForm(Request $req, Response $res): Response
    {
        Auth::startSession(Auth::isHttps($req));
        if (Auth::user()) return $this->redirect($res, self::base($req) . '/');
        $_SESSION['login_csrf'] = bin2hex(random_bytes(16));
        $ge = (string)($req->getQueryParams()['ge'] ?? '');
        $err = self::GOOGLE_ERRORS[$ge] ?? (string)($_SESSION['login_error'] ?? '');
        unset($_SESSION['login_error']);
        return $this->view($res, 'login', ['error' => $err, 'csrf' => $_SESSION['login_csrf'], 'base' => self::base($req), 'google' => GoogleAuth::enabled()]);
    }

    public function login(Request $req, Response $res): Response
    {
        Auth::startSession(Auth::isHttps($req));
        $base = self::base($req);
        $f = (array)$req->getParsedBody();
        $error = '';
        if (!hash_equals((string)($_SESSION['login_csrf'] ?? ''), (string)($f['csrf'] ?? '')) || !Auth::sameOrigin($req)) {
            $error = 'Session expired. Please try again.';
        } else {
            try {
                if (Auth::login(trim((string)($f['username'] ?? '')), (string)($f['password'] ?? ''), (string)$req->getAttribute('client_ip'))) return $this->redirect($res, $base . '/');
                $error = 'Invalid username or password.';
            } catch (ApiException $e) {
                $error = $e->status === 429 ? 'Too many attempts. Wait a minute and retry.' : ($e->status === 423 ? $e->getMessage() : 'Sign-in unavailable.');
            }
        }
        $_SESSION['login_csrf'] = bin2hex(random_bytes(16));
        return $this->view($res->withStatus(401), 'login', ['error' => $error, 'csrf' => $_SESSION['login_csrf'], 'base' => $base, 'google' => GoogleAuth::enabled()]);
    }

    /** A 200 page that navigates on; see the note in googleCallback about SameSite=Strict. */
    private function interstitial(Response $res, string $to): Response
    {
        $h = htmlspecialchars($to, ENT_QUOTES);
        $res->getBody()->write('<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=' . $h . '"><title>Signing in</title></head><body style="font-family:sans-serif;padding:2rem">Please wait&hellip; <a href="' . $h . '">Continue</a></body></html>');
        return $res->withHeader('Content-Type', 'text/html; charset=utf-8');
    }

    private function oauthCookie(Request $req, string $value, int $maxAge): string
    {
        return GoogleAuth::cookieName($req) . '=' . rawurlencode($value) . '; Path=/; Max-Age=' . $maxAge . '; HttpOnly; SameSite=Lax' . (Auth::isHttps($req) ? '; Secure' : '');
    }

    public function googleStart(Request $req, Response $res): Response
    {
        Auth::startSession(Auth::isHttps($req));
        if (Auth::user()) return $this->redirect($res, self::base($req) . '/');
        try {
            [$url, $cookie] = GoogleAuth::start($req);
            return $this->redirect($res, $url)->withAddedHeader('Set-Cookie', $this->oauthCookie($req, $cookie, 600));
        } catch (ApiException $e) {
            $_SESSION['login_error'] = $e->getMessage();
            return $this->redirect($res, self::base($req) . '/login');
        }
    }

    public function googleCallback(Request $req, Response $res): Response
    {
        Auth::startSession(Auth::isHttps($req));
        $base = self::base($req);
        $q = $req->getQueryParams();
        $clear = $this->oauthCookie($req, '', 0);
        try {
            if (isset($q['error'])) throw new ApiException(403, 'google_denied', 'Google sign-in was cancelled.');
            \Saip\RateLimiter::hit('login:' . $req->getAttribute('client_ip'), 10);
            $u = GoogleAuth::finish($req, (string)($q['code'] ?? ''), (string)($q['state'] ?? ''));
            Auth::establish($u, (string)$req->getAttribute('client_ip'), 'google');
            // A redirect chain that started at Google counts as cross-site, so the browser would withhold the SameSite=Strict session cookie
            // from a 302 to "/". An ordinary page that then navigates to "/" is a same-site navigation and carries the cookie.
            return $this->interstitial($res, $base . '/')->withAddedHeader('Set-Cookie', $clear);
        } catch (ApiException $e) {
            $code = $e->getMessage() === 'Google sign-in was cancelled.' ? 'cancelled' : (self::GOOGLE_WHY[$e->details['why'] ?? ''] ?? 'failed');
            return $this->interstitial($res, $base . '/login?ge=' . $code)->withAddedHeader('Set-Cookie', $clear);
        }
    }

    public function logout(Request $req, Response $res): Response
    {
        Auth::startSession(Auth::isHttps($req));
        $f = (array)$req->getParsedBody();
        if (hash_equals(Auth::csrf(), (string)($f['csrf'] ?? ''))) {
            if ($u = Auth::user()) Audit::log($u['username'], 'logout', null, null, $u['tenant_id'] !== null ? (int)$u['tenant_id'] : null);
            Auth::logout();
        }
        return $this->redirect($res, self::base($req) . '/login');
    }
}
