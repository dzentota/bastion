<?php
declare(strict_types=1);

namespace Bastion\Search\Domain;

/** Отрывок вокруг первого совпадения — там, где движок не умеет сам (MySQL). */
final class Snippet
{
    /** @param list<string> $terms */
    public static function make(string $text, array $terms, int $radius = 90): string
    {
        $text = preg_replace('/\s+/u', ' ', $text) ?? '';
        $at = null;
        foreach ($terms as $t) {
            $p = mb_stripos($text, $t);
            if ($p !== false && ($at === null || $p < $at)) {
                $at = $p;
            }
        }
        $start = max(0, ($at ?? 0) - $radius);
        $piece = mb_substr($text, $start, 2 * $radius);
        foreach ($terms as $t) {
            $piece = preg_replace('/(?<![\p{L}\p{N}])(' . preg_quote($t, '/') . '[\p{L}\p{N}]*)/iu', SearchHit::MARK_OPEN . '$1' . SearchHit::MARK_CLOSE, $piece) ?? $piece;
        }
        return ($start > 0 ? '…' : '') . $piece . ($start + 2 * $radius < mb_strlen($text) ? '…' : '');
    }
}
