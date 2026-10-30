<?php
declare(strict_types=1);

namespace Bastion\Content\Domain\Block;

use Bastion\Content\Domain\Title;

final class Heading implements Block
{
    public function __construct(public readonly int $level, public readonly Title $text)
    {
        if ($level < 2 || $level > 4) {
            throw new InvalidBlock('heading.level must be 2..4');
        }
    }

    public static function type(): string
    {
        return 'heading';
    }

    public function toArray(): array
    {
        return ['level' => $this->level, 'text' => $this->text->toNative()];
    }

    public static function fromArray(array $data): static
    {
        Title::tryParse($data['text'] ?? null, $text) || throw new InvalidBlock('heading.text');
        $level = $data['level'] ?? null;
        is_int($level) || throw new InvalidBlock('heading.level');
        return new static($level, $text);
    }
}
