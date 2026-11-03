<?php
declare(strict_types=1);

namespace Saip\Middleware;

use Psr\Http\Message\{ResponseInterface as Response, ServerRequestInterface as Request};
use Psr\Http\Server\{MiddlewareInterface, RequestHandlerInterface as Handler};

/** OWASP Secure Headers: strict CSP (no inline script), clickjacking, MIME sniffing, referrer, HSTS over HTTPS, cross-origin isolation. */
final class SecurityHeaders implements MiddlewareInterface
{
    private const CDN = 'https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com';
    private const CSP = "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src-elem 'self' " . self::CDN . "; style-src-attr 'unsafe-inline'; "
        . "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; img-src 'self' data: https:; connect-src 'self'; "
        . "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'";

    public function process(Request $req, Handler $next): Response
    {
        $res = $next->handle($req)
            ->withHeader('X-Content-Type-Options', 'nosniff')
            ->withHeader('X-Frame-Options', 'DENY')
            ->withHeader('Referrer-Policy', 'same-origin')
            ->withHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()')
            ->withHeader('Cross-Origin-Opener-Policy', 'same-origin')
            ->withHeader('Cross-Origin-Resource-Policy', 'same-origin')
            ->withHeader('Content-Security-Policy', self::CSP);
        $https = !empty($req->getServerParams()['HTTPS']) && $req->getServerParams()['HTTPS'] !== 'off';
        if ($https) $res = $res->withHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        return $res->hasHeader('Cache-Control') ? $res : $res->withHeader('Cache-Control', 'no-store');
    }
}
