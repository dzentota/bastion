<?php
declare(strict_types=1);

namespace Bastion\Search\Domain;

use Bastion\Content\Domain\{Entry, EntryId, Language};

/** Полнотекстовый индекс опубликованных записей, по языку (roadmap, релиз 7). */
interface SearchIndex
{
    public const PAGE = 20;

    /** Запись в том виде, в каком она опубликована; черновики не индексируются. */
    public function index(Entry $entry): void;

    public function remove(EntryId $entry): void;

    /** @return list<SearchHit> */
    public function search(Language $lang, SearchQuery $query): array;
}
