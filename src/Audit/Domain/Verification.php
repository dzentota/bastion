<?php
declare(strict_types=1);

namespace Bastion\Audit\Domain;

final class Verification
{
    private function __construct(
        public readonly bool $intact,
        public readonly int $entries,
        public readonly ?int $brokenAt,
        public readonly string $reason,
    ) {
    }

    public static function ok(int $entries): self
    {
        return new self(true, $entries, null, 'Audit trail is intact');
    }

    public static function broken(int $entries, int $at, string $reason): self
    {
        return new self(false, $entries, $at, $reason);
    }
}
