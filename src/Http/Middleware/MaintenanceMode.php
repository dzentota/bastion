<?php
declare(strict_types=1);

namespace Bastion\Http\Middleware;

use Bastion\Infrastructure\Database\Migrations\Migrator;
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};
use Psr\Http\Message\{ResponseFactoryInterface, ResponseInterface, ServerRequestInterface};
use Psr\Http\Server\{MiddlewareInterface, RequestHandlerInterface};

/**
 * Пока есть неприменённые (или подменённые) миграции, код новой версии не работает со
 * старой схемой: открыт только вход и экран «Обновить базу», остальное — 503.
 */
#[AssetId('schema-migrator')]
#[AbuserStory('half-migrated-site')]
#[Mitigation(cwe: 'CWE-754', description: 'Maintenance mode while the schema is behind the code: only login and /admin/database are routed')]
final class MaintenanceMode implements MiddlewareInterface
{
    private const OPEN = ['/admin/login', '/admin/2fa', '/admin/2fa/setup', '/admin/logout', '/admin/database'];

    public function __construct(private readonly Migrator $migrator, private readonly ResponseFactoryInterface $responses)
    {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (in_array($request->getUri()->getPath(), self::OPEN, true) || $this->migrator->state()->isCurrent()) {
            return $handler->handle($request);
        }
        if ($request->getUri()->getPath() === '/admin') {
            return $this->responses->createResponse(303)->withHeader('Location', '/admin/database');
        }
        $r = $this->responses->createResponse(503)->withHeader('Content-Type', 'text/plain; charset=utf-8')->withHeader('Retry-After', '300');
        $r->getBody()->write("The site is being updated. Please try again in a few minutes.\n");
        return $r;
    }
}
