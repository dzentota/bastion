<?php
declare(strict_types=1);

namespace Bastion\SecurityMonitoring\Domain;

/**
 * К кому относится событие: аккаунт или IP. Хранится хэшем — в журнале нет сырых логинов.
 * Ключ аккаунта и ключ IP разделены: атакующий с чужого IP не может
 * заблокировать IP админа, только его учётку (abuser story appsensor-lockout-abuse).
 */
final class ActorKey
{
    private function __construct(public readonly string $value)
    {
    }

    public static function ip(string $ip): self
    {
        return new self('ip:' . hash('sha256', $ip));
    }

    public static function account(string $usernameOrId): self
    {
        return new self('acct:' . hash('sha256', $usernameOrId));
    }
}
