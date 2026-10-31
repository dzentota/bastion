<?php
declare(strict_types=1);

namespace Bastion\Content\Infrastructure;

use Bastion\Content\Domain\{Entry, EntryId, EntryStatus, EntryType, Language, Slug, Title};
use Bastion\Content\Domain\Block\BlockList;
use Bastion\Infrastructure\Database\Row;
use SecureDb\Db;
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};

#[AbuserStory('sqli-content')]
#[Mitigation(cwe: 'CWE-89', description: 'All queries through dzentota/secure-db typed placeholders; slugs are Slug primitives')]
#[AssetId('bastion-app')]
final class EntryRepository
{
    public function __construct(private readonly Db $db)
    {
    }

    public function save(Entry $e): void
    {
        $row = [
            'type' => $e->type->value,
            'lang' => $e->lang->toNative(),
            'translation_group' => $e->translationGroup->toNative(),
            'title' => $e->title()->toNative(),
            'slug' => $e->slug()->toNative(),
            'blocks' => $e->blocks()->toJson(),
            'status' => $e->status()->value,
            'author_id' => $e->authorId,
            'published_at' => $e->publishedAt()?->format(DATE_ATOM),
            'updated_at' => gmdate(DATE_ATOM),
        ];
        $this->db->tryFlatTransaction(function (Db $db) use ($e, $row): void {
            $exists = $db->selectCell('SELECT 1 FROM ?_entries WHERE id = ?', $e->id->toNative());
            $exists
                ? $db->update('?_entries', $row, ['id' => $e->id->toNative()])
                : $db->insert('?_entries', ['id' => $e->id->toNative()] + $row);
        });
    }

    public function find(EntryId $id): ?Entry
    {
        $row = $this->db->selectRow('SELECT * FROM ?_entries WHERE id = ?', $id->toNative());
        return $row ? $this->hydrate($row) : null;
    }

    public function findPublishedBySlug(Language $lang, Slug $slug): ?Entry
    {
        $row = $this->db->selectRow(
            'SELECT * FROM ?_entries WHERE lang = ? AND slug = ? AND status = ?', $lang->toNative(), $slug->toNative(), EntryStatus::Published->value,
        );
        return $row ? $this->hydrate($row) : null;
    }

    /** Для старых адресов /{slug}: опубликованная запись с этим slug на любом языке, сначала на языке по умолчанию. */
    public function findPublishedBySlugAnyLanguage(Slug $slug, Language $preferred): ?Entry
    {
        $row = $this->db->selectRow(
            'SELECT * FROM ?_entries WHERE slug = ? AND status = ? ORDER BY CASE WHEN lang = ? THEN 0 ELSE 1 END, lang LIMIT 1',
            $slug->toNative(), EntryStatus::Published->value, $preferred->toNative(),
        );
        return $row ? $this->hydrate($row) : null;
    }

    /** Запись, которую ведёт файл репозитория (docs/adr/…), — ADR-0025. */
    public function findBySource(string $source): ?Entry
    {
        $row = $this->db->selectRow('SELECT * FROM ?_entries WHERE source = ?', $source);
        return $row ? $this->hydrate($row) : null;
    }

    public function markSource(EntryId $id, string $source): void
    {
        $this->db->update('?_entries', ['source' => $source], ['id' => $id->toNative()]);
    }

    /** Источник в репозитории или null — запись правится в CMS. До миграции 0007 колонки нет. */
    public function sourceOf(EntryId $id): ?string
    {
        try {
            $s = $this->db->selectCell('SELECT source FROM ?_entries WHERE id = ?', $id->toNative());
        } catch (\Throwable) {
            return null;
        }
        return is_string($s) && $s !== '' ? $s : null;
    }

    public function slugTaken(Language $lang, Slug $slug, ?EntryId $except = null): bool
    {
        return (bool) $this->db->selectCell(
            'SELECT 1 FROM ?_entries WHERE lang = ? AND slug = ? AND id <> ?', $lang->toNative(), $slug->toNative(), $except?->toNative() ?? '',
        );
    }

    /** @return list<Entry> все языковые варианты группы, включая черновики */
    public function translations(EntryId $group): array
    {
        return $this->hydrateAll($this->db->select('SELECT * FROM ?_entries WHERE translation_group = ? ORDER BY lang LIMIT 20', $group->toNative()));
    }

    /** @return list<Entry> опубликованные — только указанного типа (по умолчанию посты) */
    public function latest(int $limit, bool $publishedOnly, ?EntryType $type = null, ?Language $lang = null): array
    {
        $limit = max(1, min($limit, 100));
        $rows = $publishedOnly
            ? $this->db->select('SELECT * FROM ?_entries WHERE status = ? AND type = ? AND (? = \'\' OR lang = ?) ORDER BY published_at DESC LIMIT ?',
                EntryStatus::Published->value, ($type ?? EntryType::Post)->value, $l = $lang?->toNative() ?? '', $l, $limit)
            : $this->db->select('SELECT * FROM ?_entries ORDER BY updated_at DESC LIMIT ?', $limit);
        return $this->hydrateAll($rows);
    }

    /**
     * @param array<mixed> $rows
     * @return list<Entry>
     */
    private function hydrateAll(array $rows): array
    {
        return array_values(array_map(fn (mixed $r) => $this->hydrate($r), $rows));
    }

    /** Данные из БД тоже недоверенные (правило 4): парсим через примитивы. */
    private function hydrate(mixed $raw): Entry
    {
        $r = Row::of($raw);
        $publishedAt = $r->nullableStr('published_at');
        return Entry::restore(
            EntryId::fromNative($r->str('id')),
            EntryType::from($r->str('type')),
            Language::fromNative($r->str('lang')),
            EntryId::fromNative($r->str('translation_group')),
            Title::fromNative($r->str('title')),
            Slug::fromNative($r->str('slug')),
            BlockList::fromJson($r->str('blocks')),
            EntryStatus::from($r->str('status')),
            $r->str('author_id'),
            $publishedAt !== null ? new \DateTimeImmutable($publishedAt) : null,
        );
    }
}
