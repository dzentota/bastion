<?php
declare(strict_types=1);

namespace Bastion\Http\Middleware;

use Psr\Http\Message\{ResponseFactoryInterface, ResponseInterface, ServerRequestInterface};
use Psr\Http\Server\{MiddlewareInterface, RequestHandlerInterface};
use Psr\Log\LoggerInterface;

/** Внешний слой: никаких стектрейсов и деталей наружу (правило 0). */
final class ErrorHandler implements MiddlewareInterface
{
    public function __construct(private readonly ResponseFactoryInterface $responses, private readonly LoggerInterface $log)
    {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        try {
            return $handler->handle($request);
        } catch (\Throwable $e) {
            $id = bin2hex(random_bytes(6));
            $this->log->error('unhandled', ['id' => $id, 'type' => $e::class, 'msg' => $e->getMessage(), 'at' => $e->getFile() . ':' . $e->getLine()]);
            $r = $this->responses->createResponse(500)->withHeader('Content-Type', 'text/plain; charset=utf-8');
            $r->getBody()->write("Internal error. Reference: {$id}\n");
            return $r;
        }
    }
}
