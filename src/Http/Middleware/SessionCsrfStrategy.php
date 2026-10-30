<?php
declare(strict_types=1);

namespace Bastion\Http\Middleware;

use Bastion\SecurityMonitoring\Domain\{ActorKey, AppSensor, DetectionPoint};
use dzentota\Router\Middleware\Contract\CsrfProtectionStrategyInterface;
use dzentota\Router\Middleware\Exception\CsrfException;
use Dzentota\Session\Middleware\SessionMiddleware;
use Dzentota\Session\SessionManager;
use Psr\Http\Message\{ResponseInterface, ServerRequestInterface};
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};

/**
 * CSRF-стратегия для router/CsrfMiddleware поверх токена из dzentota/session.
 *
 * Почему не встроенные стратегии router: SynchronizerTokenStrategy требует атрибут session_id
 * и отдаёт токен только в заголовке ответа (неудобно для SSR-форм), а double-submit не даёт
 * токен на первом GET. TODO(router): добавить стратегию на основе SessionManager.
 */
#[AbuserStory('csrf-publish')]
#[Mitigation(cwe: 'CWE-352', description: 'dzentota/router CsrfMiddleware with session-bound synchronizer token on every state-changing request')]
#[AssetId('bastion-app')]
final class SessionCsrfStrategy implements CsrfProtectionStrategyInterface
{
    public function __construct(private readonly AppSensor $sensor)
    {
    }

    public function attachToken(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        return $response; // токен встраивается в формы через View
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
