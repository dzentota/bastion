<?php
declare(strict_types=1);

namespace Bastion\Content\Domain;

use Bastion\Content\Domain\Block\BlockList;

/** Агрегат: пост или страница. */
final class Entry
{
    private function __construct(
        public readonly EntryId $id,
        public readonly EntryType $type,
        private Title $title,
        private Slug $slug,
        private BlockList $blocks,
        private EntryStatus $status,
        public readonly string $authorId,
        private ?\DateTimeImmutable $publishedAt,
    ) {
    }

    public static function draft(EntryType $type, Title $title, Slug $slug, BlockList $blocks, string $authorId): self
    {
        return new self(EntryId::generate(), $type, $title, $slug, $blocks, EntryStatus::Draft, $authorId, null);
    }

    public static function restore(
        EntryId $id, EntryType $type, Title $title, Slug $slug, BlockList $blocks,
        EntryStatus $status, string $authorId, ?\DateTimeImmutable $publishedAt,
    ): self {
        return new self($id, $type, $title, $slug, $blocks, $status, $authorId, $publishedAt);
    }

    public function revise(Title $title, Slug $slug, BlockList $blocks): void
    {
        $this->title = $title;
        $this->slug = $slug;
        $this->blocks = $blocks;
    }

    public function publish(\DateTimeImmutable $now): void
    {
        $this->status = EntryStatus::Published;
        $this->publishedAt ??= $now;
    }

    public function title(): Title { return $this->title; }
    public function slug(): Slug { return $this->slug; }
    public function blocks(): BlockList { return $this->blocks; }
    public function status(): EntryStatus { return $this->status; }
    public function publishedAt(): ?\DateTimeImmutable { return $this->publishedAt; }
    public function isPublished(): bool { return $this->status === EntryStatus::Published; }
}
