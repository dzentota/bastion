<?php
declare(strict_types=1);

namespace Bastion\Http\Middleware;

use Bastion\IdentityAccess\Infrastructure\AccountRepository;
use Dzentota\Identity\Authenticator;
use Dzentota\Session\Middleware\SessionMiddleware;
use Dzentota\Session\SessionManager;
use Psr\Http\Message\{ResponseFactoryInterface, ResponseInterface, ServerRequestInterface};
use Psr\Http\Server\{MiddlewareInterface, RequestHandlerInterface};

/**
 * Защищает /admin/*: аутентификация через dzentota/identity (Authenticator, построенный
 * на сессии ЭТОГО запроса — см. TODO(identity) про отдельный SessionManager).
 */
final class RequireStaff implements MiddlewareInterface
{
    public const ACCOUNT = 'account';

    public function __construct(private readonly AccountRepository $accounts, private readonly ResponseFactoryInterface $responses)
    {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $session = $request->getAttribute(SessionMiddleware::SESSION_ATTRIBUTE);
        $account = $session instanceof SessionManager
            ? (new Authenticator($this->accounts, $session, AccountRepository::ARGON))->getCurrentIdentity($request)
            : null;
        if ($account === null) {
            return $this->responses->createResponse(302)->withHeader('Location', '/admin/login');
        }
        return $handler->handle($request->withAttribute(self::ACCOUNT, $account)->withAttribute(Authenticator::IDENTITY_ATTRIBUTE, $account));
    }
}
