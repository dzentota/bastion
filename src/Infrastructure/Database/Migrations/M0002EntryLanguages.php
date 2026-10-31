<?php
declare(strict_types=1);

namespace Bastion\Infrastructure\Database\Migrations;

use SecureDb\Db;

/**
 * i18n (roadmap, релиз 2): у записи появляются язык и группа переводов; slug уникален
 * в пределах языка. Существующие записи получают язык сайта по умолчанию и собственную группу.
 */
final class M0002EntryLanguages implements Migration
{
    public function __construct(private readonly string $defaultLanguage)
    {
        if (!preg_match('/^[a-z]{2}$/', $defaultLanguage)) {
            throw new \InvalidArgumentException('Invalid default language');
        }
    }

    public function id(): string
    {
        return '0002_entry_languages';
    }

    public function statements(string $driver): array
    {
        if ($driver === 'mysql') {
            return [
                "ALTER TABLE ?_entries ADD COLUMN lang VARCHAR(8) NOT NULL DEFAULT '', ADD COLUMN translation_group VARCHAR(36) NOT NULL DEFAULT ''",
                'ALTER TABLE ?_entries DROP INDEX slug, ADD UNIQUE INDEX entries_lang_slug (lang, slug), ADD INDEX entries_by_group (translation_group)',
            ];
        }
        // SQLite не умеет удалять UNIQUE колонки: пересборка таблицы
        return [
            "CREATE TABLE ?_entries_new (
                id TEXT PRIMARY KEY,
                type VARCHAR(16) NOT NULL,
                lang VARCHAR(8) NOT NULL DEFAULT '',
                translation_group TEXT NOT NULL DEFAULT '',
                title TEXT NOT NULL,
                slug TEXT NOT NULL,
                blocks TEXT NOT NULL,
                status VARCHAR(16) NOT NULL,
                author_id TEXT NOT NULL,
                published_at VARCHAR(32) NULL,
                updated_at VARCHAR(32) NOT NULL,
                UNIQUE (lang, slug)
            )",
            'INSERT INTO ?_entries_new (id, type, title, slug, blocks, status, author_id, published_at, updated_at)
                SELECT id, type, title, slug, blocks, status, author_id, published_at, updated_at FROM ?_entries',
            'DROP TABLE ?_entries',
            'ALTER TABLE ?_entries_new RENAME TO ?_entries',
            'CREATE INDEX ?_entries_by_group ON ?_entries (translation_group)',
        ];
    }

    public function apply(Db $db, string $driver): void
    {
        foreach ($this->statements($driver) as $sql) {
            $db->query($sql);
        }
        // данные зависят от настроек сайта и в контрольную сумму не входят
        $db->query("UPDATE ?_entries SET lang = ? WHERE lang = ''", $this->defaultLanguage);
        $db->query("UPDATE ?_entries SET translation_group = id WHERE translation_group = ''");
    }
}
