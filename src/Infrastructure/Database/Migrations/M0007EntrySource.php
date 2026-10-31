<?php
declare(strict_types=1);

namespace Bastion\Infrastructure\Database\Migrations;

use SecureDb\Db;

/** Записи, источник которых — файл в репозитории (ADR): в CMS только для чтения (ADR-0025). */
final class M0007EntrySource implements Migration
{
    public function id(): string
    {
        return '0007_entry_source';
    }

    public function statements(string $driver): array
    {
        return ['ALTER TABLE ?_entries ADD COLUMN source VARCHAR(200) NULL'];
    }

    public function apply(Db $db, string $driver): void
    {
        foreach ($this->statements($driver) as $sql) {
            $db->query($sql);
        }
    }
}
