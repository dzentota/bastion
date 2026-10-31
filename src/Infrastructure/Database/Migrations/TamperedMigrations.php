<?php
declare(strict_types=1);

namespace Bastion\Infrastructure\Database\Migrations;

final class TamperedMigrations extends \RuntimeException
{
    /** @param list<string> $ids */
    public function __construct(public readonly array $ids)
    {
        parent::__construct('Applied migrations do not match the code: ' . implode(', ', $ids));
    }
}
