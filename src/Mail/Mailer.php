<?php
declare(strict_types=1);

namespace Bastion\Mail;

use Bastion\IdentityAccess\Domain\StaffEmail;

/** Порт отправки писем. Только текстовые письма с фиксированными шаблонами. */
interface Mailer
{
    public function isConfigured(): bool;

    public function send(StaffEmail $to, string $subject, string $text): void;
}
