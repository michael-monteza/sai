<?php
declare(strict_types=1);

namespace Saip\Middleware;

use Psr\Http\Message\{ResponseInterface as Response, ServerRequestInterface as Request};
use Psr\Http\Server\{MiddlewareInterface, RequestHandlerInterface as Handler};
use Saip\{Audit, Config};
use Saip\Http\Controller;

/** Outermost: request id, trusted client IP, audit context. */
final class RequestContext implements MiddlewareInterface
{
    public function process(Request $req, Handler $next): Response
    {
        $id = bin2hex(random_bytes(8));
        $ip = (string)($req->getServerParams()['REMOTE_ADDR'] ?? '0.0.0.0');
        $fwd = $req->getHeaderLine('X-Forwarded-For');
        if ($fwd !== '' && in_array($ip, (array)Config::get('trusted_proxies', []), true)) {
            $first = trim(explode(',', $fwd)[0]);
            if (filter_var($first, FILTER_VALIDATE_IP)) $ip = $first;
        }
        Controller::$requestId = $id;
        Audit::$ip = $ip;
        Audit::$requestId = $id;
        return $next->handle($req->withAttribute('client_ip', $ip)->withAttribute('request_id', $id))->withHeader('X-Request-Id', $id);
    }
}
