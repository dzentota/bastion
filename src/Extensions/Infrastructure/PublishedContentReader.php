<?php
declare(strict_types=1);

namespace Bastion\Extensions\Infrastructure;

use Bastion\Content\Domain\Entry;
use Bastion\Content\Infrastructure\EntryRepository;
use Bastion\Extension\Api\{ContentReader, PublishedEntry};

/** Фасад content.read: только опубликованные записи и только скаляры. */
final class PublishedContentReader implements ContentReader
{
    public function __construct(private readonly EntryRepository $entries)
    {
    }

    public function latest(int $limit): array
    {
        return array_map(static fn (Entry $e) => new PublishedEntry(
            $e->title()->toNative(), '/' . $e->slug()->toNative(), $e->publishedAt()?->format('Y-m-d') ?? '',
        ), $this->entries->latest(max(1, min($limit, 20)), true));
    }
}
