<?php
declare(strict_types=1);

namespace Bastion\Infrastructure\Database\Migrations;

use Bastion\Content\Domain\Block\BlockList;
use Bastion\Infrastructure\Database\Row;
use Bastion\Search\Domain\SearchText;
use SecureDb\Db;

/** Полнотекстовый поиск (roadmap, релиз 7). Индекс заполняется опубликованными записями. */
final class M0006SearchIndex implements Migration
{
    public function id(): string
    {
        return '0006_search_index';
    }

    public function statements(string $driver): array
    {
        if ($driver === 'mysql') {
            return ['CREATE TABLE ?_search (
                entry_id VARCHAR(36) PRIMARY KEY,
                lang VARCHAR(8) NOT NULL,
                title TEXT NOT NULL,
                body LONGTEXT NOT NULL,
                FULLTEXT KEY search_text (title, body)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'];
        }
        return ["CREATE VIRTUAL TABLE ?_search USING fts5(entry_id UNINDEXED, lang UNINDEXED, title, body, tokenize = 'unicode61 remove_diacritics 2')"];
    }

    public function apply(Db $db, string $driver): void
    {
        foreach ($this->statements($driver) as $sql) {
            $db->query($sql);
        }
        foreach ($db->select("SELECT id, lang, title, blocks FROM ?_entries WHERE status = 'published'") as $raw) {
            $r = Row::of($raw);
            try {
                $body = SearchText::of(BlockList::fromJson($r->str('blocks')));
            } catch (\Throwable) {
                continue; // повреждённая запись не должна блокировать миграцию; проиндексируется при публикации
            }
            $db->insert('?_search', ['entry_id' => $r->str('id'), 'lang' => $r->str('lang'), 'title' => $r->str('title'), 'body' => $body]);
        }
    }
}
