<?php
declare(strict_types=1);

namespace Bastion\Infrastructure\Database;

/**
 * Типизированный доступ к строке результата. Данные из БД — тоже недоверенный ввод (правило 4):
 * неожиданный тип = исключение, а не тихое приведение.
 */
final class Row
{
    /** @param array<array-key, mixed> $data */
    private function __construct(private readonly array $data)
    {
    }

    public static function of(mixed $row): self
    {
        return is_array($row) ? new self($row) : throw new \UnexpectedValueException('Row expected');
    }

    public function str(string $col): string
    {
        $v = $this->data[$col] ?? null;
        return is_string($v) ? $v : (is_int($v) ? (string) $v : throw new \UnexpectedValueException("Column {$col}: string expected"));
    }

    public function int(string $col): int
    {
        $v = $this->data[$col] ?? null;
        return match (true) {
            is_int($v) => $v,
            is_string($v) && preg_match('/^-?\d+$/', $v) === 1 => (int) $v,
            default => throw new \UnexpectedValueException("Column {$col}: integer expected"),
        };
    }

    public function nullableInt(string $col): ?int
    {
        return ($this->data[$col] ?? null) === null ? null : $this->int($col);
    }
}
