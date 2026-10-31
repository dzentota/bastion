<?php
declare(strict_types=1);

namespace Bastion\Content\Domain;

/** Результат проверки цепочки ревизий записи. */
final class RevisionChain
{
    /** @param list<Revision> $revisions от новых к старым */
    public function __construct(public readonly array $revisions, public readonly bool $intact, public readonly ?int $brokenAt = null)
    {
    }
}
