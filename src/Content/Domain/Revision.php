<?php
declare(strict_types=1);

namespace Bastion\Content\Domain;

use Bastion\Content\Domain\Block\BlockList;

/** Неизменяемый снимок содержимого записи. Номер seq растёт с 1 в пределах записи. */
final class Revision
{
    public function __construct(
        public readonly EntryId $id,
        public readonly EntryId $entryId,
        public readonly int $seq,
        public readonly Title $title,
        public readonly Slug $slug,
        public readonly BlockList $blocks,
        public readonly string $authorId,
        public readonly \DateTimeImmutable $createdAt,
        /** откат: номер ревизии, содержимое которой скопировано */
        public readonly ?int $restoredFrom = null,
    ) {
    }

    public function sameContentAs(Title $title, Slug $slug, BlockList $blocks): bool
    {
        return $this->title->toNative() === $title->toNative() && $this->slug->toNative() === $slug->toNative()
            && $this->blocks->toJson() === $blocks->toJson();
    }
}
