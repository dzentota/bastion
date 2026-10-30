<?php
declare(strict_types=1);

namespace Bastion\Http\Middleware;

use Bastion\SecurityMonitoring\Domain\{ActorKey, AppSensor, DetectionPoint};
use dzentota\Router\Middleware\Contract\{CsrfProtectionStrategyInterface, CsrfTokenProviderInterface};
use dzentota\Router\Middleware\Exception\CsrfException;
use Dzentota\Session\Middleware\SessionMiddleware;
use Dzentota\Session\SessionManager;
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};
use Psr\Http\Message\{ResponseInterface, ServerRequestInterface};

/**
 * CSRF-стратегия для router/CsrfMiddleware поверх пула токенов dzentota/session.
 * Токены живут в зашифрованной сессии в БД — отдельный PSR-16 кэш (как для
 * SynchronizerTokenStrategy) на shared-хостинге не нужен.
 */
#[AssetId('bastion-app')]
#[AbuserStory('csrf-publish')]
#[Mitigation(cwe: 'CWE-352', description: 'dzentota/router CsrfMiddleware with session-bound synchronizer token pool on every state-changing request')]
final class SessionCsrfStrategy implements CsrfProtectionStrategyInterface, CsrfTokenProviderInterface
{
    public function __construct(private readonly AppSensor $sensor)
    {
    }

    public function prepareRequest(ServerRequestInterface $request, string $tokenAttribute): ServerRequestInterface
    {
        $session = $request->getAttribute(SessionMiddleware::SESSION_ATTRIBUTE);
        return $session instanceof SessionManager
            ? $request->withAttribute($tokenAttribute, $session->generateCsrfToken()->toNative())
            : $request;
    }

    public function attachToken(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        return $response; // токен встраивается в формы через View (атрибут csrf_token)
    }

    public function validateRequest(ServerRequestInterface $request): void
    {
        $session = $request->getAttribute(SessionMiddleware::SESSION_ATTRIBUTE);
        $body = $request->getParsedBody();
        $token = $request->getHeaderLine('X-CSRF-TOKEN') ?: (is_array($body) && is_string($body['_token'] ?? null) ? $body['_token'] : '');
        if (!$session instanceof SessionManager || $token === '' || !$session->isCsrfTokenValid($token)) {
            $this->sensor->event(DetectionPoint::RE6, ActorKey::ip((string) ($request->getServerParams()['REMOTE_ADDR'] ?? 'unknown')));
            throw new CsrfException('Invalid CSRF token');
        }
    }
}
