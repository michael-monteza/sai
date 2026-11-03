<?php
declare(strict_types=1);

namespace Saip\Modules;

use Psr\Http\Message\{ResponseInterface as Response, ServerRequestInterface as Request};
use Saip\{DomainRegistry, SysmonCatalog};
use Saip\Http\Controller;
use Saip\Middleware\RequirePermission as Need;
use Slim\Routing\RouteCollectorProxy as Group;

/** Sysmon capability reference: events tracked, how they map to SAIP JSON, and sample payloads. */
final class SysmonModule extends Controller
{
    public static function register(Group $g): void
    {
        $g->get('/sysmon', [self::class, 'catalog'])->add(new Need('collectors.read'));
    }

    public function catalog(Request $req, Response $res): Response
    {
        $mon = DomainRegistry::monitoring($this->tid($req));
        return $this->json($res, ['events' => SysmonCatalog::events(), 'mapping' => SysmonCatalog::mapping(), 'samples' => SysmonCatalog::samples(),
            'monitoring' => ['network_events' => $mon['network_events'], 'discovery' => $mon['discovery']]]);
    }
}
