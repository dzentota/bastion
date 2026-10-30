<?php
declare(strict_types=1);

namespace Bastion\Http\Middleware;

use Bastion\SecurityMonitoring\Domain\{ActorKey, AppSensor, ResponseAction};
use Psr\Http\Message\{ResponseFactoryInterface, ResponseInterface, ServerRequestInterface};
use Psr\Http\Server\{MiddlewareInterface, RequestHandlerInterface};

/** Применяет активный ответ Throttle для IP к изменяющим запросам. */
final class AppSensorGate implements MiddlewareInterface
{
    public function __construct(private readonly AppSensor $sensor, private readonly ResponseFactoryInterface $responses)
    {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $ip = ActorKey::ip((string) ($request->getServerParams()['REMOTE_ADDR'] ?? 'unknown'));
        if ($request->getMethod() !== 'GET' && $this->sensor->isActive(ResponseAction::Throttle, $ip)) {
            return $this->responses->createResponse(429)->withHeader('Retry-After', '600');
        }
        return $handler->handle($request);
    }
}
