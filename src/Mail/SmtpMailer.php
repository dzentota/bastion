<?php
declare(strict_types=1);

namespace Bastion\Mail;

use Bastion\IdentityAccess\Domain\StaffEmail;
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};
use Symfony\Component\Mailer\Mailer as SymfonyMailer;
use Symfony\Component\Mailer\Transport\Smtp\EsmtpTransport;
use Symfony\Component\Mime\Email;

#[AssetId('bastion-app')]
#[AbuserStory('smtp-cleartext')]
#[Mitigation(cwe: 'CWE-319', description: 'SMTP only over implicit TLS (465) or mandatory STARTTLS (587/2525) with certificate verification; plaintext fallback disabled; hostnames only')]
#[AbuserStory('mail-header-injection')]
#[Mitigation(cwe: 'CWE-93', description: 'Recipients are StaffEmail primitives (no CR/LF), subjects fixed by code, headers built by symfony/mime, plain-text body only')]
final class SmtpMailer implements Mailer
{
    private readonly SymfonyMailer $mailer;

    public function __construct(private readonly SmtpConfig $config)
    {
        $transport = new EsmtpTransport($config->host, $config->port, $config->port === 465);
        if ($config->port !== 465) {
            $transport->setRequireTls(true); // без STARTTLS — ошибка, а не отправка открытым текстом
        }
        $transport->setUsername($config->user);
        $transport->setPassword($config->password());
        $this->mailer = new SymfonyMailer($transport);
    }

    public function isConfigured(): bool
    {
        return true;
    }

    public function send(StaffEmail $to, string $subject, string $text): void
    {
        if (preg_match('/[\r\n]/', $subject)) {
            throw new \InvalidArgumentException('Subject must be a single line');
        }
        $this->mailer->send((new Email())
            ->from($this->config->from->toNative())
            ->to($to->toNative())
            ->subject($subject)
            ->text($text));
    }
}
