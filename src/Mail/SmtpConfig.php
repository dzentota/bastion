<?php
declare(strict_types=1);

namespace Bastion\Mail;

use Bastion\IdentityAccess\Domain\StaffEmail;
use dzentota\TypedValue\Security\{ProhibitedFromLogs, SecurityStrategy};

final class SmtpConfig implements ProhibitedFromLogs
{
    public function __construct(
        public readonly string $host,
        public readonly int $port,
        public readonly string $user,
        #[\SensitiveParameter] private readonly string $password,
        public readonly StaffEmail $from,
    ) {
        if (!preg_match('/^[A-Za-z0-9.-]{1,253}$/', $host) || filter_var($host, FILTER_VALIDATE_IP) !== false) {
            throw new \InvalidArgumentException('SMTP host must be a hostname (TLS certificates are issued for names)');
        }
        if (!in_array($port, [465, 587, 2525], true)) {
            throw new \InvalidArgumentException('SMTP port must be 465 (TLS) or 587/2525 (STARTTLS)');
        }
        if ($user === '' || strlen($user) > 254 || preg_match('/[\r\n]/', $user . $password)) {
            throw new \InvalidArgumentException('Invalid SMTP credentials');
        }
    }

    public function password(): string
    {
        return $this->password;
    }

    public static function getLoggingSecurityStrategy(): SecurityStrategy
    {
        return SecurityStrategy::PROHIBIT;
    }

    public function getSafeLoggableRepresentation(): string
    {
        return '[smtp-config]';
    }

    /** @return array<string, string|int> */
    public function __debugInfo(): array
    {
        return ['host' => $this->host, 'port' => $this->port, 'password' => '***'];
    }
}
