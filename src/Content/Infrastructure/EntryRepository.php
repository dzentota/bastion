<?php
declare(strict_types=1);

namespace Bastion\Content\Infrastructure;

use Bastion\Content\Domain\{Entry, EntryId, EntryStatus, EntryType, Slug, Title};
use Bastion\Content\Domain\Block\BlockList;
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

    public function findPublishedBySlug(Slug $slug): ?Entry
    {
        $row = $this->db->selectRow(
            'SELECT * FROM ?_entries WHERE slug = ? AND status = ?', $slug->toNative(), EntryStatus::Published->value,
        );
        return $row ? $this->hydrate($row) : null;
    }

    public function slugTaken(Slug $slug, ?EntryId $except = null): bool
    {
        return (bool) $this->db->selectCell(
            'SELECT 1 FROM ?_entries WHERE slug = ? AND id <> ?', $slug->toNative(), $except?->toNative() ?? '',
        );
    }

    /** @return list<Entry> */
    public function latest(int $limit, bool $publishedOnly): array
    {
        $limit = max(1, min($limit, 100));
        $rows = $publishedOnly
            ? $this->db->select('SELECT * FROM ?_entries WHERE status = ? ORDER BY published_at DESC LIMIT ?', EntryStatus::Published->value, $limit)
            : $this->db->select('SELECT * FROM ?_entries ORDER BY updated_at DESC LIMIT ?', $limit);
        return array_map($this->hydrate(...), $rows);
    }

    /** Данные из БД тоже недоверенные (правило 4): парсим через примитивы. */
    private function hydrate(array $r): Entry
    {
        return Entry::restore(
            EntryId::fromNative($r['id']),
            EntryType::from($r['type']),
            Title::fromNative($r['title']),
            Slug::fromNative($r['slug']),
            BlockList::fromJson($r['blocks']),
            EntryStatus::from($r['status']),
            $r['author_id'],
            $r['published_at'] !== null ? new \DateTimeImmutable($r['published_at']) : null,
        );
    }
}
