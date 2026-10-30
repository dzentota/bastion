<?php
declare(strict_types=1);

namespace Bastion\IdentityAccess\Domain;

enum Role: string
{
    case Admin = 'admin';
    case Editor = 'editor';
    case Author = 'author';

    /** @return list<Capability> */
    public function capabilities(): array
    {
        return match ($this) {
            self::Admin => Capability::cases(),
            self::Editor => [Capability::ContentEdit, Capability::ContentEditOthers, Capability::ContentPublish, Capability::MediaUpload],
            self::Author => [Capability::ContentEdit, Capability::MediaUpload],
        };
    }

    public function can(Capability $c): bool
    {
        return in_array($c, $this->capabilities(), true);
    }

    /** ADR-0009: второй фактор обязателен для Admin и Editor. */
    public function requiresSecondFactor(): bool
    {
        return $this !== self::Author;
    }
}
