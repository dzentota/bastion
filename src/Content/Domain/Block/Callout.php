<?php
declare(strict_types=1);

namespace Bastion\Content\Domain\Block;

/** Выделенная врезка: заметка, предупреждение или опасность. */
final class Callout implements Block
{
    public const VARIANTS = ['note', 'warning', 'danger'];

    public function __construct(public readonly string $variant, public readonly BlockText $text)
    {
        if (!in_array($variant, self::VARIANTS, true)) {
            throw new InvalidBlock('callout.variant');
        }
    }

    public static function type(): string
    {
        return 'callout';
    }

    public function toArray(): array
    {
        return ['variant' => $this->variant, 'text' => $this->text->toNative()];
    }

    public static function fromArray(array $data): static
    {
        BlockText::tryParse($data['text'] ?? null, $text) || throw new InvalidBlock('callout.text');
        $variant = $data['variant'] ?? 'note';
        is_string($variant) || throw new InvalidBlock('callout.variant');
        return new static($variant, $text);
    }
}
