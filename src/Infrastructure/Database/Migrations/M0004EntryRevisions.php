<?php
declare(strict_types=1);

namespace Bastion\Infrastructure\Database\Migrations;

use SecureDb\Db;

/**
 * Ревизии (roadmap, релиз 3): неизменяемый снимок на каждое сохранение, цепочка HMAC
 * на запись. entries.published_revision — какая ревизия сейчас на сайте.
 * Записи, созданные до миграции, получают первую ревизию при первом сохранении.
 */
final class M0004EntryRevisions implements Migration
{
    public function id(): string
    {
        return '0004_entry_revisions';
    }

    public function statements(string $driver): array
    {
        $text = $driver === 'mysql' ? 'LONGTEXT' : 'TEXT';
        $suffix = $driver === 'mysql' ? ' ENGINE=InnoDB DEFAULT CHARSET=utf8mb4' : '';
        return [
            "CREATE TABLE ?_entry_revisions (
                id VARCHAR(36) PRIMARY KEY,
                entry_id VARCHAR(36) NOT NULL,
                seq INTEGER NOT NULL,
                title {$text} NOT NULL,
                slug VARCHAR(96) NOT NULL,
                blocks {$text} NOT NULL,
                author_id VARCHAR(36) NOT NULL,
                created_at VARCHAR(32) NOT NULL,
                restored_from INTEGER NULL,
                mac CHAR(64) NOT NULL,
                UNIQUE (entry_id, seq)
            ){$suffix}",
            'ALTER TABLE ?_entries ADD COLUMN published_revision VARCHAR(36) NULL',
        ];
    }

    public function apply(Db $db, string $driver): void
    {
        foreach ($this->statements($driver) as $sql) {
            $db->query($sql);
        }
    }
}
