<?php
declare(strict_types=1);

namespace Bastion\Extensions\Application;

final class GateViolation
{
    public function __construct(public readonly string $file, public readonly int $line, public readonly string $rule)
    {
    }

    public function __toString(): string
    {
        return "{$this->file}:{$this->line}: {$this->rule}";
    }
}
