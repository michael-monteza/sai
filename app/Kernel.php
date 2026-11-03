<?php
declare(strict_types=1);

namespace Saip;

use Saip\Http\ErrorHandler;
use Saip\Middleware\{ConsoleSession, RequestContext, SecurityHeaders};
use Saip\Modules\{AdminModule, AnalyticsModule, CollectorApiModule, DiscoveryModule, FleetModule, GovernanceModule, IntegrationsModule, InventoryModule, PagesModule, RegistryModule, SettingsModule, SiemModule, SysmonModule};
use Slim\App;
use Slim\Factory\AppFactory;
use Slim\Routing\RouteCollectorProxy as Group;

/** Builds the Slim application: middleware stack and one registration call per module. */
final class Kernel
{
    /** Console modules: each registers its own routes and per-route permissions. */
    private const CONSOLE_MODULES = [AdminModule::class, InventoryModule::class, RegistryModule::class, DiscoveryModule::class, FleetModule::class, GovernanceModule::class, AnalyticsModule::class, SettingsModule::class, IntegrationsModule::class, SysmonModule::class];

    public static function create(): App
    {
        $app = AppFactory::create();
        $script = str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/'));
        $app->setBasePath($script === '/' || $script === '.' ? '' : rtrim($script, '/'));
        $app->addBodyParsingMiddleware();      // form posts (login/logout); JSON bodies are decoded by Controller::body() with size limits
        $app->addRoutingMiddleware();

        $errors = $app->addErrorMiddleware(false, true, true);
        $errors->setDefaultErrorHandler(new ErrorHandler($app->getResponseFactory()));
        $app->add(new SecurityHeaders());
        $app->add(new RequestContext());       // outermost: request id + audit context for everything below

        PagesModule::register($app);
        $app->group('/api/v1', static function (Group $api): void {
            CollectorApiModule::register($api);
            SiemModule::register($api);
            $api->group('/console', static function (Group $c): void {
                foreach (self::CONSOLE_MODULES as $module) $module::register($c);
            })->add(new ConsoleSession());
        });
        return $app;
    }
}
