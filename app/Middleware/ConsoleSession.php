<?php
declare(strict_types=1);

namespace Saip\Middleware;

use Psr\Http\Message\{ResponseInterface as Response, ServerRequestInterface as Request};
use Psr\Http\Server\{MiddlewareInterface, RequestHandlerInterface as Handler};
use Saip\{ApiException, Audit};
use Saip\Security\Auth;

/**
 * Console API guard (OWASP ASVS V3/V4, CSRF Prevention Cheat Sheet):
 * valid session (401); on every state-changing method a synchronizer token in X-CSRF-Token (compared in constant time)
 * AND a same-origin Origin/Referer check (defence in depth, on top of SameSite=Strict cookies and the JSON-only content type).
 */
final class ConsoleSession implements MiddlewareInterface
{
    public function process(Request $req, Handler $next): Response
    {
        $https = Auth::isHttps($req);
        if (!isset($req->getCookieParams()[$https ? '__Host-saip_sid' : 'saip_sid'])) throw new ApiException(401, 'unauthenticated', 'Sign in required.');   // no cookie, no session
        Auth::startSession($https);
        $u = Auth::user();
        if (!$u) throw new ApiException(401, 'unauthenticated', 'Sign in required.');
        if (!in_array($req->getMethod(), ['GET', 'HEAD', 'OPTIONS'], true)) {
            $deny = null;
            if (!hash_equals(Auth::csrf(), $req->getHeaderLine('X-CSRF-Token'))) $deny = 'token';
            elseif (!Auth::sameOrigin($req)) $deny = 'origin';
            if ($deny !== null) {
                Audit::log($u['username'], 'csrf_failed', $req->getUri()->getPath(), ['check' => $deny], $u['tenant_id'] !== null ? (int)$u['tenant_id'] : null);
                throw new ApiException(403, 'csrf_failed', 'Invalid CSRF token. Reload the page.');
            }
        }
        return $next->handle($req->withAttribute('user', $u));
    }
}
