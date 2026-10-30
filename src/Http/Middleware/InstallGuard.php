<?php
declare(strict_types=1);

namespace Bastion\Http\Middleware;

use Bastion\Installation\Paths;
use Psr\Http\Message\{ResponseFactoryInterface, ResponseInterface, ServerRequestInterface};
use Psr\Http\Server\{MiddlewareInterface, RequestHandlerInterface};
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};

/** До установки доступен только /install; после — /install не существует (reinstall-over-live). */
#[AbuserStory('reinstall-over-live')]
#[Mitigation(cwe: 'CWE-284', description: 'Installer route returns 404 once installed.lock exists; installer refuses a non-empty accounts table')]
#[AssetId('installer')]
final class InstallGuard implements MiddlewareInterface
{
    public function __construct(private readonly Paths $paths, private readonly ResponseFactoryInterface $responses)
    {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $isInstallRoute = $request->getUri()->getPath() === '/install';
        if (!$this->paths->isInstalled() && !$isInstallRoute) {
            return $this->responses->createResponse(302)->withHeader('Location', '/install');
        }
        if ($this->paths->isInstalled() && $isInstallRoute) {
            return $this->responses->createResponse(404);
        }
        return $handler->handle($request);
    }
}
