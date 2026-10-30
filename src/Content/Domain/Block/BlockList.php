<?php
declare(strict_types=1);

namespace Bastion\Content\Domain\Block;

/**
 * Упорядоченный список блоков Entry. Парсится из недоверенного JSON целиком или не парсится вовсе.
 * Неизвестный тип блока = ошибка (правило 4: все источники равны).
 */
final class BlockList implements \IteratorAggregate, \Countable
{
    public const MAX_BLOCKS = 500;

    /** @var array<string, class-string<Block>> */
    private const TYPES = [
        'paragraph' => Paragraph::class,
        'heading' => Heading::class,
        'quote' => Quote::class,
        'image' => Image::class,
    ];

    /** @param list<Block> $blocks */
    private function __construct(private readonly array $blocks)
    {
    }

    public static function of(Block ...$blocks): self
    {
        if (count($blocks) > self::MAX_BLOCKS) {
            throw new InvalidBlock('Too many blocks');
        }
        return new self(array_values($blocks));
    }

    /** @throws InvalidBlock */
    public static function fromJson(string $json): self
    {
        if (strlen($json) > 2_000_000) {
            throw new InvalidBlock('Content too large');
        }
        try {
            $raw = json_decode($json, true, 4, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw new InvalidBlock('Malformed block JSON');
        }
        if (!is_array($raw) || !array_is_list($raw)) {
            throw new InvalidBlock('Blocks must be a list');
        }
        $blocks = [];
        foreach ($raw as $item) {
            if (!is_array($item) || !is_string($item['type'] ?? null) || !isset(self::TYPES[$item['type']])) {
                throw new InvalidBlock('Unknown block type');
            }
            $data = $item['data'] ?? null;
            if (!is_array($data)) {
                throw new InvalidBlock('Block data must be an object');
            }
            $blocks[] = (self::TYPES[$item['type']])::fromArray($data);
        }
        return self::of(...$blocks);
    }

    public function toJson(): string
    {
        return json_encode(
            array_map(static fn (Block $b) => ['type' => $b::type(), 'data' => $b->toArray()], $this->blocks),
            JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE,
        );
    }

    /** @return list<\Bastion\Media\Domain\MediaId> */
    public function mediaIds(): array
    {
        $ids = [];
        foreach ($this->blocks as $b) {
            if ($b instanceof Image) {
                $ids[] = $b->media;
            }
        }
        return $ids;
    }

    public function getIterator(): \ArrayIterator
    {
        return new \ArrayIterator($this->blocks);
    }

    public function count(): int
    {
        return count($this->blocks);
    }
}
