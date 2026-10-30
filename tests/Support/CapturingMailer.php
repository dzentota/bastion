<?php
declare(strict_types=1);

namespace Bastion\Tests\Support;

use Bastion\IdentityAccess\Domain\StaffEmail;
use Bastion\Mail\Mailer;

final class CapturingMailer implements Mailer
{
    /** @var list<array{to: string, subject: string, text: string}> */
    public array $sent = [];

    public function isConfigured(): bool
    {
        return true;
    }

    public function send(StaffEmail $to, string $subject, string $text): void
    {
        $this->sent[] = ['to' => $to->toNative(), 'subject' => $subject, 'text' => $text];
    }
}
