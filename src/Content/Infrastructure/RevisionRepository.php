<?php
declare(strict_types=1);

namespace Bastion\Content\Infrastructure;

use Bastion\Content\Domain\{Entry, EntryId, Revision, RevisionChain, Slug, Title};
use Bastion\Content\Domain\Block\BlockList;
use Bastion\Infrastructure\Database\Row;
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};
use Psr\Clock\ClockInterface;
use SecureDb\Db;

/**
 * Ревизии только добавляются: методов изменения и удаления нет. Каждая ревизия подписана
 * HMAC, включающим MAC предыдущей, — подмена, удаление или вставка в середину видны.
 */
#[AssetId('bastion-app')]
#[AbuserStory('revision-tamper')]
#[Mitigation(cwe: 'CWE-354', description: 'Append-only revisions; each row carries an HMAC (derived key outside the DB) chained to the previous revision, verified when history is shown and before publishing')]
final class RevisionRepository
{
    public const MAX_HISTORY = 200;

    public function __construct(private readonly Db $db, private readonly string $key, private readonly ClockInterface $clock)
    {
    }

    /** Новая ревизия, если содержимое отличается от последней. */
    public function record(Entry $entry, Title $title, Slug $slug, BlockList $blocks, string $authorId, ?int $restoredFrom = null): Revision
    {
        $rev = $this->db->tryFlatTransaction(function () use ($entry, $title, $slug, $blocks, $authorId, $restoredFrom): Revision {
            $head = $this->head($entry->id);
            if ($head !== null && $restoredFrom === null && $head->sameContentAs($title, $slug, $blocks)) {
                return $head;
            }
            $prevMac = $head !== null ? $this->macOf($head->id) : '';
            $rev = new Revision(EntryId::generate(), $entry->id, ($head->seq ?? 0) + 1, $title, $slug, $blocks, $authorId, $this->clock->now(), $restoredFrom);
            $this->db->insert('?_entry_revisions', $this->row($rev) + ['mac' => $this->mac($rev, $prevMac)]);
            return $rev;
        });
        return $rev instanceof Revision ? $rev : throw new \LogicException('Revision transaction returned no revision');
    }

    /** Записи до релиза 3: первая ревизия — текущее содержимое строки entries. */
    public function ensureBaseline(Entry $entry): void
    {
        if ($this->head($entry->id) === null) {
            $rev = $this->record($entry, $entry->title(), $entry->slug(), $entry->blocks(), $entry->authorId);
            if ($entry->isPublished()) {
                $this->markPublished($entry->id, $rev->id);
            }
        }
    }

    public function head(EntryId $entry): ?Revision
    {
        $row = $this->db->selectRow('SELECT * FROM ?_entry_revisions WHERE entry_id = ? ORDER BY seq DESC LIMIT 1', $entry->toNative());
        return $row ? $this->hydrate($row) : null;
    }

    public function find(EntryId $entry, int $seq): ?Revision
    {
        $row = $this->db->selectRow('SELECT * FROM ?_entry_revisions WHERE entry_id = ? AND seq = ?', $entry->toNative(), $seq);
        return $row ? $this->hydrate($row) : null;
    }

    public function findById(EntryId $id): ?Revision
    {
        $row = $this->db->selectRow('SELECT * FROM ?_entry_revisions WHERE id = ?', $id->toNative());
        return $row ? $this->hydrate($row) : null;
    }

    public function publishedId(EntryId $entry): ?string
    {
        $id = $this->db->selectCell('SELECT published_revision FROM ?_entries WHERE id = ?', $entry->toNative());
        return is_string($id) ? $id : null;
    }

    public function markPublished(EntryId $entry, EntryId $revision): void
    {
        $this->db->update('?_entries', ['published_revision' => $revision->toNative()], ['id' => $entry->toNative()]);
    }

    /** История от новых к старым с проверкой всей цепочки. */
    public function chain(EntryId $entry): RevisionChain
    {
        $rows = $this->db->select('SELECT * FROM ?_entry_revisions WHERE entry_id = ? ORDER BY seq ASC', $entry->toNative());
        $prev = '';
        $expect = 1;
        $revisions = [];
        $brokenAt = null;
        foreach ($rows as $raw) {
            $r = Row::of($raw);
            try {
                $rev = $this->hydrate($raw);
            } catch (\Throwable) {
                $brokenAt ??= $r->int('seq'); // строка не проходит доменную проверку — тоже подмена
                continue;
            }
            if ($brokenAt === null && ($rev->seq !== $expect || !hash_equals($this->mac($rev, $prev), $r->str('mac')))) {
                $brokenAt = $rev->seq;
            }
            $prev = $r->str('mac');
            $expect = $rev->seq + 1;
            $revisions[] = $rev;
        }
        return new RevisionChain(array_slice(array_reverse($revisions), 0, self::MAX_HISTORY), $brokenAt === null, $brokenAt);
    }

    private function macOf(EntryId $revision): string
    {
        $mac = $this->db->selectCell('SELECT mac FROM ?_entry_revisions WHERE id = ?', $revision->toNative());
        return is_string($mac) ? $mac : '';
    }

    private function mac(Revision $r, string $prevMac): string
    {
        return hash_hmac('sha256', json_encode([
            $r->entryId->toNative(), $r->seq, $r->title->toNative(), $r->slug->toNative(), $r->blocks->toJson(),
            $r->authorId, $r->createdAt->format(DATE_ATOM), $r->restoredFrom, $prevMac,
        ], JSON_THROW_ON_ERROR), $this->key);
    }

    /** @return array<string, string|int|null> */
    private function row(Revision $r): array
    {
        return [
            'id' => $r->id->toNative(), 'entry_id' => $r->entryId->toNative(), 'seq' => $r->seq,
            'title' => $r->title->toNative(), 'slug' => $r->slug->toNative(), 'blocks' => $r->blocks->toJson(),
            'author_id' => $r->authorId, 'created_at' => $r->createdAt->format(DATE_ATOM), 'restored_from' => $r->restoredFrom,
        ];
    }

    private function hydrate(mixed $raw): Revision
    {
        $r = Row::of($raw);
        return new Revision(
            EntryId::fromNative($r->str('id')), EntryId::fromNative($r->str('entry_id')), $r->int('seq'),
            Title::fromNative($r->str('title')), Slug::fromNative($r->str('slug')), BlockList::fromJson($r->str('blocks')),
            $r->str('author_id'), new \DateTimeImmutable($r->str('created_at')), $r->nullableInt('restored_from'),
        );
    }
}
