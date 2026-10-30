<?php
declare(strict_types=1);

namespace Bastion\Tests\Support;

use Psr\Clock\ClockInterface;

final class FrozenClock implements ClockInterface
{
    public function __construct(public \DateTimeImmutable $now = new \DateTimeImmutable('2026-10-30T12:00:00Z'))
    {
    }

    public function now(): \DateTimeImmutable
    {
        return $this->now;
    }

    public function advance(int $seconds): void
    {
        $this->now = $this->now->modify("+{$seconds} seconds");
    }
}
