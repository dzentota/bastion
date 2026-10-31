<?php
declare(strict_types=1);

namespace Bastion\Content\Infrastructure;

use Bastion\Content\Domain\{EntryId, EntryStatus, EntryType, Language, MenuPosition};
use Bastion\Infrastructure\Database\Row;
use SecureDb\Db;

/** Меню сайта: опубликованные страницы, отмеченные в редакторе. */
final class MenuRepository
{
    public const MAX_ITEMS = 10;

    public function __construct(private readonly Db $db)
    {
    }

    public function place(EntryId $entry, ?MenuPosition $position): void
    {
        $this->db->tryFlatTransaction(function (Db $db) use ($entry, $position): void {
            $db->query('DELETE FROM ?_menu WHERE entry_id = ?', $entry->toNative());
            if ($position !== null) {
                $db->insert('?_menu', ['entry_id' => $entry->toNative(), 'position' => $position->toInt()]);
            }
        });
    }

    public function positionOf(EntryId $entry): ?MenuPosition
    {
        $p = $this->db->selectCell('SELECT position FROM ?_menu WHERE entry_id = ?', $entry->toNative());
        return is_numeric($p) && MenuPosition::tryParse((string) (int) $p, $pos) ? $pos : null;
    }

    /** @return list<array{title: string, url: string}> меню языка: у каждого перевода своё место */
    public function items(Language $lang): array
    {
        $rows = $this->db->select(
            'SELECT e.title, e.slug FROM ?_menu m JOIN ?_entries e ON e.id = m.entry_id
             WHERE e.status = ? AND e.type = ? AND e.lang = ? ORDER BY m.position, e.title LIMIT ?',
            EntryStatus::Published->value, EntryType::Page->value, $lang->toNative(), self::MAX_ITEMS,
        );
        return array_values(array_map(static function (mixed $raw) use ($lang): array {
            $r = Row::of($raw);
            return ['title' => $r->str('title'), 'url' => '/' . $lang->toNative() . '/' . $r->str('slug')];
        }, $rows));
    }
}
