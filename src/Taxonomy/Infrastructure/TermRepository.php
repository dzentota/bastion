<?php
declare(strict_types=1);

namespace Bastion\Taxonomy\Infrastructure;

use Bastion\Content\Domain\{EntryId, EntryStatus, EntryType, Language, Slug};
use Bastion\Taxonomy\Domain\{PageNumber, Term, TermKind, TermList};
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};
use SecureDb\Db;

#[AbuserStory('term-enumeration-dos')]
#[Mitigation(cwe: 'CWE-400', description: 'Listings: fixed page size, page number capped (no deep OFFSET), only indexed lookups by (kind, slug); unknown terms 404 without scanning entries; per-entry term limits; global cap on distinct terms per kind')]
#[AssetId('db')]
final class TermRepository
{
    public const PAGE_SIZE = 20;
    public const MAX_TERMS_PER_KIND = 1000;

    public function __construct(private readonly Db $db)
    {
    }

    /** Заменяет термины вида у записи. False — превышен общий лимит терминов (новые не создаются). */
    public function assign(EntryId $entry, TermList $list): bool
    {
        $ok = true;
        $this->db->tryFlatTransaction(function (Db $db) use ($entry, $list, &$ok): void {
            $known = self::strings($db->selectCol('SELECT slug FROM ?_terms WHERE kind = ?', $list->kind->value));
            $new = array_filter($list->terms, static fn (Term $t) => !in_array($t->slug->toNative(), $known, true));
            if (count($known) + count($new) > self::MAX_TERMS_PER_KIND) {
                $ok = false;
                return;
            }
            foreach ($new as $t) {
                $db->insert('?_terms', ['kind' => $t->kind->value, 'slug' => $t->slug->toNative()]);
            }
            $db->query('DELETE FROM ?_entry_terms WHERE entry_id = ? AND kind = ?', $entry->toNative(), $list->kind->value);
            foreach ($list->terms as $t) {
                $db->insert('?_entry_terms', ['entry_id' => $entry->toNative(), 'kind' => $t->kind->value, 'slug' => $t->slug->toNative()]);
            }
        });
        return $ok;
    }

    public function forEntry(EntryId $entry, TermKind $kind): TermList
    {
        $slugs = self::strings($this->db->selectCol(
            'SELECT slug FROM ?_entry_terms WHERE entry_id = ? AND kind = ? ORDER BY slug', $entry->toNative(), $kind->value,
        ));
        // данные из БД тоже недоверенные (правило 4)
        return TermList::of($kind, ...array_map(Slug::fromNative(...), $slugs));
    }

    public function exists(TermKind $kind, Slug $slug): bool
    {
        return (bool) $this->db->selectCell('SELECT 1 FROM ?_terms WHERE kind = ? AND slug = ?', $kind->value, $slug->toNative());
    }

    /**
     * Id опубликованных записей термина, новые первыми; на одну больше PAGE_SIZE — признак следующей страницы.
     * @return list<string>
     */
    public function publishedEntryIds(Term $term, Language $lang, PageNumber $page): array
    {
        return self::strings($this->db->selectCol(
            'SELECT e.id FROM ?_entry_terms t JOIN ?_entries e ON e.id = t.entry_id
             WHERE t.kind = ? AND t.slug = ? AND e.status = ? AND e.type = ? AND e.lang = ?
             ORDER BY e.published_at DESC LIMIT ? OFFSET ?',
            $term->kind->value, $term->slug->toNative(), EntryStatus::Published->value, EntryType::Post->value, $lang->toNative(),
            self::PAGE_SIZE + 1, ($page->toInt() - 1) * self::PAGE_SIZE,
        ));
    }

    /**
     * @param array<mixed> $col
     * @return list<string>
     */
    private static function strings(array $col): array
    {
        return array_values(array_map(static fn (mixed $v): string => is_string($v) ? $v : throw new \UnexpectedValueException('Expected string column'), $col));
    }
}
