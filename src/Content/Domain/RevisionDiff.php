<?php
declare(strict_types=1);

namespace Bastion\Content\Domain;

use Bastion\Content\Domain\Block\Block;
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};

/**
 * Построчное сравнение двух ревизий (LCS). Строки — заголовок, slug и текст блоков
 * с типом блока. Результат — плоский список операций; экранирует шаблон.
 */
#[AssetId('bastion-app')]
#[AbuserStory('diff-dos')]
#[Mitigation(cwe: 'CWE-400', description: 'LCS table is bounded: above MAX_LINES per side the diff is not computed and both versions are shown in full')]
final class RevisionDiff
{
    public const MAX_LINES = 600;

    /** @param list<array{op: 'same'|'add'|'del', text: string}> $ops */
    private function __construct(public readonly array $ops, public readonly bool $tooLarge)
    {
    }

    public static function between(Revision $old, Revision $new): self
    {
        $a = self::lines($old);
        $b = self::lines($new);
        if (count($a) > self::MAX_LINES || count($b) > self::MAX_LINES) {
            return new self(array_merge(
                array_map(static fn (string $t) => ['op' => 'del', 'text' => $t], $a),
                array_map(static fn (string $t) => ['op' => 'add', 'text' => $t], $b),
            ), true);
        }
        return new self(self::lcs($a, $b), false);
    }

    public function changed(): bool
    {
        foreach ($this->ops as $op) {
            if ($op['op'] !== 'same') {
                return true;
            }
        }
        return false;
    }

    /** @return list<string> */
    private static function lines(Revision $r): array
    {
        $lines = ['# ' . $r->title->toNative(), '/' . $r->slug->toNative()];
        foreach ($r->blocks as $block) {
            if (!$block instanceof Block) {
                continue;
            }
            $data = $block->toArray();
            $field = static fn (string $k): string => is_scalar($data[$k] ?? null) ? (string) $data[$k] : '';
            $text = $block::type() === 'image' ? '[' . $field('media') . '] ' . $field('alt') : $field('text');
            // параметр блока — часть метки: смена языка кода или типа врезки тоже видна в сравнении
            $option = $field('language') . $field('variant') . (($data['header'] ?? false) === true ? 'header' : '');
            $label = $block::type() . ($option !== '' ? '[' . $option . ']' : '');
            foreach (explode("\n", $text) as $line) {
                $lines[] = $label . ': ' . $line;
            }
        }
        return $lines;
    }

    /**
     * @param list<string> $a
     * @param list<string> $b
     * @return list<array{op: 'same'|'add'|'del', text: string}>
     */
    private static function lcs(array $a, array $b): array
    {
        $n = count($a);
        $m = count($b);
        // длины общих подпоследовательностей суффиксов; SplFixedArray — без накладных расходов массивов PHP
        $len = new \SplFixedArray(($n + 1) * ($m + 1));
        $at = static fn (int $i, int $j): int => is_int($v = $len[$i * ($m + 1) + $j]) ? $v : 0;
        for ($i = $n; $i >= 0; $i--) {
            for ($j = $m; $j >= 0; $j--) {
                $len[$i * ($m + 1) + $j] = ($i === $n || $j === $m) ? 0
                    : ($a[$i] === $b[$j] ? $at($i + 1, $j + 1) + 1 : max($at($i + 1, $j), $at($i, $j + 1)));
            }
        }
        $ops = [];
        $i = $j = 0;
        while ($i < $n && $j < $m) {
            if ($a[$i] === $b[$j]) {
                $ops[] = ['op' => 'same', 'text' => $a[$i]];
                $i++;
                $j++;
            } elseif ($at($i + 1, $j) >= $at($i, $j + 1)) {
                $ops[] = ['op' => 'del', 'text' => $a[$i++]];
            } else {
                $ops[] = ['op' => 'add', 'text' => $b[$j++]];
            }
        }
        while ($i < $n) {
            $ops[] = ['op' => 'del', 'text' => $a[$i++]];
        }
        while ($j < $m) {
            $ops[] = ['op' => 'add', 'text' => $b[$j++]];
        }
        return $ops;
    }
}
