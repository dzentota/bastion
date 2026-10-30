<?php
declare(strict_types=1);

namespace Bastion\Mail;

use Bastion\IdentityAccess\Domain\StaffEmail;

final class UnconfiguredMailer implements Mailer
{
    public function isConfigured(): bool
    {
        return false;
    }

    public function send(StaffEmail $to, string $subject, string $text): void
    {
        throw new \LogicException('Outgoing mail is not configured');
    }
}
