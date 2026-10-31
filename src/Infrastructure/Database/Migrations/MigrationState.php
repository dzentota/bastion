<?php
declare(strict_types=1);

namespace Bastion\Infrastructure\Database\Migrations;

final class MigrationState
{
    /**
     * @param list<string> $pending id неприменённых миграций
     * @param list<string> $tampered id применённых миграций, чья сумма не совпадает с кодом,
     *                               или записанных в базе, но отсутствующих в коде
     */
    public function __construct(public readonly array $pending, public readonly array $tampered)
    {
    }

    public function isCurrent(): bool
    {
        return $this->pending === [] && $this->tampered === [];
    }
}
