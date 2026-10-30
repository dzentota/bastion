<?php
declare(strict_types=1);

namespace Bastion\IdentityAccess\Application;

use Bastion\IdentityAccess\Domain\Account;
use Bastion\IdentityAccess\Infrastructure\AccountRepository;
use dzentota\Router\Middleware\Cache\ArrayCache;
use Dzentota\Identity\Authenticator;
use Dzentota\Identity\Exception\AuthenticationException;
use Dzentota\Session\Cookie\CookieManager;
use Dzentota\Session\SessionManager;
use Dzentota\Session\Storage\CacheStorage;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Проверка пароля через dzentota/identity (argon2id, dummy-hash против timing-атак, rehash).
 *
 * TODO(identity): Authenticator::login() сразу помечает сессию аутентифицированной и не
 * поддерживает шаг второго фактора. Пока библиотека не получит публичный verify(),
 * используем одноразовую in-memory сессию, которая выбрасывается — реальная сессия
 * аутентифицируется только после 2FA (TwoStepLogin).
 */
final class PasswordVerifier
{
    public function __construct(private readonly AccountRepository $accounts)
    {
    }

    public function verify(ServerRequestInterface $request, string $username, #[\SensitiveParameter] string $password): ?Account
    {
        $scratch = new SessionManager(new CacheStorage(new ArrayCache()), new CookieManager());
        try {
            $identity = (new Authenticator($this->accounts, $scratch, AccountRepository::ARGON))
                ->login($request->withoutAttribute('session'), $username, $password);
        } catch (AuthenticationException) {
            return null;
        }
        return $identity instanceof Account ? $identity : null;
    }
}
