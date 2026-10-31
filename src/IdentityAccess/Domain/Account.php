<?php
declare(strict_types=1);

namespace Bastion\IdentityAccess\Domain;

use Dzentota\Identity\Identity;

final class Account implements Identity
{
    public function __construct(
        public readonly AccountId $id,
        public readonly Username $username,
        public readonly Role $role,
        public readonly bool $hasTotp,
        /** язык интерфейса админки; null — язык сайта по умолчанию */
        public readonly ?\Bastion\Content\Domain\Language $locale = null,
    ) {
    }

    public function getId(): string
    {
        return $this->id->toNative();
    }
}
