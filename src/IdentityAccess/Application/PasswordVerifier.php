<?php
declare(strict_types=1);

namespace Bastion\IdentityAccess\Application;

use Bastion\IdentityAccess\Domain\Account;
use Bastion\IdentityAccess\Infrastructure\AccountRepository;
use Dzentota\Identity\Authenticator;

/**
 * Проверка пароля через dzentota/identity (argon2id, dummy-hash против timing-атак, rehash).
 * Сессию не трогает: аутентифицирует её только TwoStepLogin после второго фактора.
 */
final class PasswordVerifier
{
    public function __construct(private readonly AccountRepository $accounts)
    {
    }

    public function verify(string $username, #[\SensitiveParameter] string $password): ?Account
    {
        $identity = (new Authenticator($this->accounts, null, AccountRepository::ARGON))->verifyCredentials($username, $password);
        return $identity instanceof Account ? $identity : null;
    }
}
