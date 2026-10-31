<?php
declare(strict_types=1);

namespace Bastion\Content\Domain\Block;

use Bastion\Shared\Domain\BoundedText;
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};

/**
 * Таблица из простого текста: строка — ряд, ячейки через «|». Хранится как текст
 * (глубина JSON блоков ограничена), разбирается и проверяется целиком при создании.
 */
#[AssetId('bastion-app')]
#[AbuserStory('table-bomb')]
#[Mitigation(cwe: 'CWE-400', description: 'Tables are bounded: at most 50 rows, 8 columns and 500 characters per cell, validated before storage')]
final class Table implements Block
{
    public const MAX_ROWS = 50;
    public const MAX_COLS = 8;
    public const MAX_CELL = 500;

    /** @param non-empty-list<list<string>> $rows */
    private function __construct(public readonly array $rows, public readonly bool $header)
    {
    }

    public static function type(): string
    {
        return 'table';
    }

    public function toArray(): array
    {
        return ['text' => $this->text(), 'header' => $this->header];
    }

    /** Канонический текст: ячейки через « | », ряды через перевод строки. */
    public function text(): string
    {
        return implode("\n", array_map(static fn (array $r) => implode(' | ', $r), $this->rows));
    }

    public static function fromArray(array $data): static
    {
        $text = $data['text'] ?? null;
        if (!is_string($text) || !BoundedText::check($text, 1, self::MAX_ROWS * self::MAX_COLS * (self::MAX_CELL + 3), true)->success()) {
            throw new InvalidBlock('table.text');
        }
        $rows = [];
        foreach (preg_split('/\r\n|\n|\r/', trim($text)) ?: [] as $line) {
            if (trim($line) === '') {
                continue;
            }
            $cells = array_map('trim', explode('|', $line));
            if (count($cells) > self::MAX_COLS) {
                throw new InvalidBlock('table.columns');
            }
            foreach ($cells as $c) {
                if (mb_strlen($c) > self::MAX_CELL) {
                    throw new InvalidBlock('table.cell');
                }
            }
            $rows[] = $cells;
        }
        if ($rows === [] || count($rows) > self::MAX_ROWS) {
            throw new InvalidBlock('table.rows');
        }
        $header = $data['header'] ?? false;
        is_bool($header) || throw new InvalidBlock('table.header');
        return new static($rows, $header);
    }
}
