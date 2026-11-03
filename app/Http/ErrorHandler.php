<?php
declare(strict_types=1);

namespace Saip\Http;

use Psr\Http\Message\{ResponseFactoryInterface, ResponseInterface as Response, ServerRequestInterface as Request};
use Saip\ApiException;
use Slim\Exception\{HttpMethodNotAllowedException, HttpNotFoundException};

/** Every failure becomes {"error":{code,message,details?},"request_id"}; internals are logged, never returned (OWASP A05/A09). */
final class ErrorHandler
{
    public function __construct(private readonly ResponseFactoryInterface $factory) {}

    public function __invoke(Request $req, \Throwable $e, bool $display, bool $log, bool $logDetails): Response
    {
        if ($e instanceof HttpNotFoundException) $e = new ApiException(404, 'not_found', 'Unknown endpoint.');
        elseif ($e instanceof HttpMethodNotAllowedException) $e = new ApiException(405, 'method_not_allowed', 'Method not allowed for this endpoint.');
        elseif (!$e instanceof ApiException) {
            error_log('[SAIP ' . Controller::$requestId . '] ' . $e);
            $e = new ApiException(500, 'server_error', 'Internal server error.');
        }
        $err = ['code' => $e->errorCode, 'message' => $e->getMessage()];
        if ($e->details) $err['details'] = $e->details;
        $res = $this->factory->createResponse($e->status)->withHeader('Content-Type', 'application/json; charset=utf-8');
        foreach ($e->headers as $k => $v) $res = $res->withHeader($k, $v);
        $res->getBody()->write(json_encode(['error' => $err, 'request_id' => Controller::$requestId], JSON_UNESCAPED_SLASHES));
        return $res;
    }
}
