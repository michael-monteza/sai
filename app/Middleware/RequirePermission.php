<?php
declare(strict_types=1);

namespace Saip\Middleware;

use Psr\Http\Message\{ResponseInterface as Response, ServerRequestInterface as Request};
use Psr\Http\Server\{MiddlewareInterface, RequestHandlerInterface as Handler};
use Saip\{ApiException, Audit};
use Saip\Security\Rbac;

/** Route guard (deny by default): `->add(new RequirePermission('registry.write'))`. Denials are audited. */
final class RequirePermission implements MiddlewareInterface
{
    public function __construct(private readonly string $permission) {}

    public function process(Request $req, Handler $next): Response
    {
        $u = $req->getAttribute('user');
        if (!$u || !Rbac::can($u['role'], $this->permission)) {
            if ($u) Audit::log($u['username'], 'access_denied', $req->getMethod() . ' ' . $req->getUri()->getPath(), ['permission' => $this->permission, 'role' => $u['role']], $u['tenant_id'] !== null ? (int)$u['tenant_id'] : null);
            throw new ApiException(403, 'forbidden', 'Your role does not permit this action.');
        }
        return $next->handle($req);
    }
}
