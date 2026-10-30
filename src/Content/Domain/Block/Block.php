<?php
declare(strict_types=1);

namespace Bastion\Content\Domain\Block;

/**
 * Блок контента — неизменяемый Value Object. Хранит только структурированные данные,
 * никогда HTML (ADR-0007). HTML строит BlockHtmlRenderer.
 */
interface Block
{
    public static function type(): string;

    /** @return array<string, mixed> только скаляры и списки скаляров */
    public function toArray(): array;

    /** @param array<string, mixed> $data  @throws InvalidBlock */
    public static function fromArray(array $data): static;
}
