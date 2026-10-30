<?php
declare(strict_types=1);

namespace Bastion\Content\Domain\Block;

use Bastion\Media\Domain\{AltText, MediaId};

/** Изображение из медиатеки. Хранит только ссылку на MediaId — никаких URL от пользователя. */
final class Image implements Block
{
    public function __construct(public readonly MediaId $media, public readonly AltText $alt)
    {
    }

    public static function type(): string
    {
        return 'image';
    }

    public function toArray(): array
    {
        return ['media' => $this->media->toNative(), 'alt' => $this->alt->toNative()];
    }

    public static function fromArray(array $data): static
    {
        MediaId::tryParse($data['media'] ?? null, $media) || throw new InvalidBlock('image.media');
        AltText::tryParse($data['alt'] ?? '', $alt) || throw new InvalidBlock('image.alt');
        return new static($media, $alt);
    }
}
