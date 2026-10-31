<?php
declare(strict_types=1);

namespace Bastion\Infrastructure\Database\Migrations;

use SecureDb\Db;

/** Иерархия страниц (roadmap, релиз 4): родитель в том же языке и порядок среди соседей. */
final class M0005PageTree implements Migration
{
    public function id(): string
    {
        return '0005_page_tree';
    }

    public function statements(string $driver): array
    {
        return [
            'ALTER TABLE ?_entries ADD COLUMN parent_id VARCHAR(36) NULL',
            'ALTER TABLE ?_entries ADD COLUMN position INTEGER NOT NULL DEFAULT 0',
            'CREATE INDEX ' . ($driver === 'mysql' ? 'entries_by_parent' : '?_entries_by_parent') . ' ON ?_entries (lang, parent_id, position)',
        ];
    }

    public function apply(Db $db, string $driver): void
    {
        foreach ($this->statements($driver) as $sql) {
            $db->query($sql);
        }
    }
}
