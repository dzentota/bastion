<?php
declare(strict_types=1);

namespace Bastion\Media\Infrastructure;

use Bastion\Media\Domain\{DisplayName, MediaId, MediaItem, MediaKind};
use Bastion\Infrastructure\Database\Row;
use SecureDb\Db;

final class MediaRepository
{
    public function __construct(private readonly Db $db)
    {
    }

    public function add(MediaItem $m): void
    {
        $this->db->insert('?_media', [
            'id' => $m->id->toNative(),
            'kind' => $m->kind->value,
            'name' => $m->name->toNative(),
            'bytes' => $m->bytes,
            'width' => $m->width,
            'height' => $m->height,
            'uploaded_by' => $m->uploadedBy,
            'uploaded_at' => $m->uploadedAt->getTimestamp(),
        ]);
    }

    public function find(MediaId $id): ?MediaItem
    {
        $row = $this->db->selectRow('SELECT * FROM ?_media WHERE id = ?', $id->toNative());
        return $row ? $this->hydrate(Row::of($row)) : null;
    }

    /** @return list<MediaItem> */
    public function latest(int $limit): array
    {
        $rows = $this->db->select('SELECT * FROM ?_media ORDER BY uploaded_at DESC LIMIT ?', max(1, min($limit, 200)));
        return array_values(array_map(fn (mixed $r) => $this->hydrate(Row::of($r)), $rows));
    }

    /** @return array{count: int, bytes: int} */
    public function usageSince(string $accountId, int $since): array
    {
        $row = Row::of($this->db->selectRow(
            'SELECT COUNT(*) AS c, COALESCE(SUM(bytes), 0) AS b FROM ?_media WHERE uploaded_by = ? AND uploaded_at > ?', $accountId, $since,
        ));
        return ['count' => $row->int('c'), 'bytes' => $row->int('b')];
    }

    private function hydrate(Row $r): MediaItem
    {
        return new MediaItem(
            MediaId::fromNative($r->str('id')),
            MediaKind::from($r->str('kind')),
            DisplayName::fromNative($r->str('name')),
            $r->int('bytes'),
            $r->nullableInt('width'),
            $r->nullableInt('height'),
            $r->str('uploaded_by'),
            (new \DateTimeImmutable())->setTimestamp($r->int('uploaded_at')),
        );
    }
}
