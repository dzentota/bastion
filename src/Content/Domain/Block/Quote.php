<?php
declare(strict_types=1);

namespace Bastion\Content\Domain\Block;

final class Quote implements Block
{
    public function __construct(public readonly BlockText $text)
    {
    }

    public static function type(): string
    {
        return 'quote';
    }

    public function toArray(): array
    {
        return ['text' => $this->text->toNative()];
    }

    public static function fromArray(array $data): static
    {
        BlockText::tryParse($data['text'] ?? null, $text) || throw new InvalidBlock('quote.text');
        return new static($text);
    }
}
