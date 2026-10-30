<?php
declare(strict_types=1);

namespace Bastion\Audit\Domain;

final class AuditEntry
{
    public function __construct(
        public readonly int $seq,
        public readonly int $at,
        public readonly AuditAction $action,
        public readonly ?string $actor,
        public readonly ?string $subject,
        public readonly string $ip,
        public readonly string $mac,
    ) {
    }

    /** Каноническое представление для MAC: фиксированный порядок полей, JSON без неоднозначностей. */
    public function canonical(): string
    {
        return json_encode([$this->seq, $this->at, $this->action->value, $this->actor, $this->subject, $this->ip], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }
}
