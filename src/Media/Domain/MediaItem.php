<?php
declare(strict_types=1);

namespace Bastion\Media\Domain;

final class MediaItem
{
    public function __construct(
        public readonly MediaId $id,
        public readonly MediaKind $kind,
        public readonly DisplayName $name,
        public readonly int $bytes,
        public readonly ?int $width,
        public readonly ?int $height,
        public readonly string $uploadedBy,
        public readonly \DateTimeImmutable $uploadedAt,
    ) {
    }

    public function key(): StorageKey
    {
        return StorageKey::for($this->id, $this->kind);
    }

    public function url(): string
    {
        return '/media/' . $this->id->toNative();
    }
}
