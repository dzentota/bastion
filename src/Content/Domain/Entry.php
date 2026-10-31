<?php
declare(strict_types=1);

namespace Bastion\Content\Domain;

use Bastion\Content\Domain\Block\BlockList;

/** Агрегат: пост или страница на одном языке. Переводы — записи с общей translationGroup. */
final class Entry
{
    private function __construct(
        public readonly EntryId $id,
        public readonly EntryType $type,
        public readonly Language $lang,
        public readonly EntryId $translationGroup,
        private Title $title,
        private Slug $slug,
        private BlockList $blocks,
        private EntryStatus $status,
        public readonly string $authorId,
        private ?\DateTimeImmutable $publishedAt,
    ) {
    }

    public static function draft(EntryType $type, Language $lang, Title $title, Slug $slug, BlockList $blocks, string $authorId): self
    {
        $id = EntryId::generate();
        return new self($id, $type, $lang, $id, $title, $slug, $blocks, EntryStatus::Draft, $authorId, null);
    }

    /** Черновик перевода: тот же тип и группа, блоки — отправная точка для переводчика. */
    public function translate(Language $lang, Title $title, Slug $slug, string $authorId): self
    {
        return new self(EntryId::generate(), $this->type, $lang, $this->translationGroup, $title, $slug, $this->blocks, EntryStatus::Draft, $authorId, null);
    }

    public static function restore(
        EntryId $id, EntryType $type, Language $lang, EntryId $translationGroup, Title $title, Slug $slug, BlockList $blocks,
        EntryStatus $status, string $authorId, ?\DateTimeImmutable $publishedAt,
    ): self {
        return new self($id, $type, $lang, $translationGroup, $title, $slug, $blocks, $status, $authorId, $publishedAt);
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

    /** Публичный адрес: /{язык}/{slug}. */
    public function path(): string { return '/' . $this->lang->toNative() . '/' . $this->slug->toNative(); }
    public function title(): Title { return $this->title; }
    public function slug(): Slug { return $this->slug; }
    public function blocks(): BlockList { return $this->blocks; }
    public function status(): EntryStatus { return $this->status; }
    public function publishedAt(): ?\DateTimeImmutable { return $this->publishedAt; }
    public function isPublished(): bool { return $this->status === EntryStatus::Published; }
}
