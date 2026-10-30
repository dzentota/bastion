<?php
declare(strict_types=1);

namespace Bastion\Tests\Support;

use Bastion\Audit\Domain\{AuditAction, AuditTrail};

final class RecordingAuditTrail implements AuditTrail
{
    /** @var list<array{AuditAction, ?string, ?string, string}> */
    public array $records = [];

    public function record(AuditAction $action, ?string $actor, ?string $subject, string $ip): void
    {
        $this->records[] = [$action, $actor, $subject, $ip];
    }
}
