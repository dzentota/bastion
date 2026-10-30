<?php
declare(strict_types=1);

namespace Bastion\Http\Middleware;

use Bastion\IdentityAccess\Application\TwoStepLogin;
use Bastion\IdentityAccess\Infrastructure\AccountRepository;
use Dzentota\Identity\Authenticator;
use Dzentota\Session\Middleware\SessionMiddleware;
use Dzentota\Session\SessionManager;
use Psr\Http\Message\{ResponseFactoryInterface, ResponseInterface, ServerRequestInterface};
use Psr\Http\Server\{MiddlewareInterface, RequestHandlerInterface};

/** Защищает /admin/*: аутентификация через dzentota/identity (сессия берётся из запроса). */
final class RequireStaff implements MiddlewareInterface
{
    public const ACCOUNT = 'account';

    public function __construct(private readonly AccountRepository $accounts, private readonly ResponseFactoryInterface $responses)
    {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $account = $request->getAttribute(SessionMiddleware::SESSION_ATTRIBUTE) instanceof SessionManager
            ? (new Authenticator($this->accounts, null, AccountRepository::ARGON))->getCurrentIdentity($request)
            : null;
        if ($account === null) {
            return $this->responses->createResponse(302)->withHeader('Location', '/admin/login');
        }
        // Сессия, начатая до смены пароля, недействительна (reset-session-persistence).
        // (сессия гарантирована: без неё $account выше был бы null)
        $session = $request->getAttribute(SessionMiddleware::SESSION_ATTRIBUTE);
        $version = $session->get(TwoStepLogin::CREDENTIALS_VERSION);
        if (!is_int($version) || $version !== $this->accounts->credentialsVersion($account->getId())) {
            $session->destroy();
            return $this->responses->createResponse(302)->withHeader('Location', '/admin/login');
        }
        return $handler->handle($request->withAttribute(self::ACCOUNT, $account)->withAttribute(Authenticator::IDENTITY_ATTRIBUTE, $account));
    }
}
