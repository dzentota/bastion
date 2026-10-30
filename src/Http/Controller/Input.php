<?php
declare(strict_types=1);

namespace Bastion\Http\Controller;

use Psr\Http\Message\ServerRequestInterface;

/** Доступ к полям формы: только строки, только известные ключи (правило 0: минимум ввода). */
final class Input
{
    public static function string(ServerRequestInterface $r, string $key, int $maxBytes = 20000): string
    {
        $body = $r->getParsedBody();
        $v = is_array($body) ? ($body[$key] ?? '') : '';
        return is_string($v) && strlen($v) <= $maxBytes ? $v : '';
    }

    /** @return list<array<string, string>> */
    public static function rows(ServerRequestInterface $r, string $key, int $max): array
    {
        $body = $r->getParsedBody();
        $rows = is_array($body) && is_array($body[$key] ?? null) ? $body[$key] : [];
        $out = [];
        foreach (array_slice($rows, 0, $max) as $row) {
            if (is_array($row)) {
                $out[] = array_filter($row, 'is_string');
            }
        }
        return $out;
    }
}
