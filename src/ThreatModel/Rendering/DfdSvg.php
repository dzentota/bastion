<?php
declare(strict_types=1);

namespace Bastion\ThreatModel\Rendering;

use Bastion\ThreatModel\Domain\ThreatModelData;
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};

/**
 * Диаграмма потоков данных (DFD) как SVG, построенная на сервере. Слева — внешние источники,
 * в середине — зоны доверия (пунктирные рамки) с их компонентами, справа — внешние службы.
 * Форма по нотации DFD: внешняя сущность — прямоугольник, процесс — скруглённый, хранилище —
 * открытые линии сверху и снизу. Потоки пронумерованы; таблица под диаграммой — её текстовая версия.
 * Разметку SVG задаёт только этот класс; весь текст из модели экранирован.
 */
#[AssetId('bastion-app')]
#[AbuserStory('svg-injection')]
#[Mitigation(cwe: 'CWE-79', description: 'The data-flow diagram is generated SVG: element names and geometry come from code, every model string is escaped as text, no markup or attributes are taken from the export')]
final class DfdSvg
{
    private const W = 196;
    private const H = 48;
    private const GAP = 20;
    private const COL = [16, 300, 600, 900];
    private const BOX_PAD = 30;

    /** @return array{svg: string, numbers: array<string, int>} номера потоков для таблицы */
    public static function render(ThreatModelData $m, string $title): array
    {
        $flows = $m->flows;
        $inFlow = [];
        $hasIn = $hasOut = [];
        foreach ($flows as $f) {
            $inFlow[$f['from']] = $inFlow[$f['to']] = true;
            $hasOut[$f['from']] = true;
            $hasIn[$f['to']] = true;
        }
        // на диаграмме — только участники потоков (злоумышленники живут в историях, не в потоках)
        $nodes = array_values(array_filter($m->components, static fn (array $c) => isset($inFlow[$c['id']])));
        $pos = [];
        $y = ['left' => 40, 'right' => 40];
        $boxes = [];
        $cursor = 40;
        foreach ($m->boundaries as $b) {
            $members = array_values(array_filter($nodes, static fn (array $c) => $c['boundary'] === $b['id']));
            if ($members === []) {
                continue;
            }
            $a = array_values(array_filter($members, static fn (array $c) => isset($hasOut[$c['id']])));
            $z = array_values(array_filter($members, static fn (array $c) => !isset($hasOut[$c['id']])));
            $top = $cursor + self::BOX_PAD;
            foreach ([[$a, self::COL[1]], [$z, self::COL[2]]] as [$group, $x]) {
                foreach ($group as $i => $c) {
                    $pos[$c['id']] = [$x, $top + $i * (self::H + self::GAP)];
                }
            }
            $rows = max(count($a), count($z));
            $height = self::BOX_PAD + $rows * (self::H + self::GAP) + 4;
            $boxes[] = [$b['name'], $cursor, $height];
            $cursor += $height + 28;
        }
        foreach ($nodes as $c) {
            if ($c['boundary'] !== null) {
                continue;
            }
            $side = isset($hasIn[$c['id']]) && !isset($hasOut[$c['id']]) ? 'right' : 'left';
            $pos[$c['id']] = [$side === 'left' ? self::COL[0] : self::COL[3], $y[$side]];
            $y[$side] += self::H + self::GAP;
        }
        $width = self::COL[3] + self::W + 24;
        $height = max($cursor, $y['left'], $y['right']) + 12;

        $svg = sprintf('<svg class="dfd" viewBox="0 0 %d %d" role="img" aria-labelledby="dfd-title" xmlns="http://www.w3.org/2000/svg">', $width, $height)
            . '<title id="dfd-title">' . self::e($title) . '</title>'
            . '<defs><marker id="dfd-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 10 5 0 10Z" class="dfd-head"/></marker></defs>';
        foreach ($boxes as [$name, $top, $h]) {
            $svg .= sprintf('<g class="dfd-boundary"><rect x="%d" y="%d" width="%d" height="%d"/><text x="%d" y="%d">%s</text></g>',
                self::COL[1] - 14, $top, self::COL[2] + self::W - self::COL[1] + 28, $h, self::COL[1] - 4, $top + 18, self::e($name));
        }
        $numbers = [];
        $edges = '';
        $incoming = array_count_values(array_column($flows, 'to'));
        foreach ($flows as $i => $f) {
            if (!isset($pos[$f['from']], $pos[$f['to']])) {
                continue;
            }
            $n = $i + 1;
            $numbers[$f['id']] = $n;
            [$x1, $y1] = $pos[$f['from']];
            [$x2, $y2] = $pos[$f['to']];
            $forward = $x2 >= $x1 + self::W;
            if ($x1 === $x2) {
                // в одной колонке: дуга справа
                [$sx, $sy, $tx, $ty] = [$x1 + self::W, $y1 + self::H / 2, $x2 + self::W, $y2 + self::H / 2];
                $c1 = $sx + 48;
                $pts = [$sx, $sy, $c1, $sy, $c1, $ty, $tx + 2, $ty];
            } else {
                [$sx, $tx] = $forward ? [$x1 + self::W, $x2] : [$x1, $x2 + self::W];
                [$sy, $ty] = [$y1 + self::H / 2, $y2 + self::H / 2];
                $dx = ($tx - $sx) / 2;
                $pts = [$sx, $sy, $sx + $dx, $sy, $tx - $dx, $ty, $tx, $ty];
            }
            $path = vsprintf('M%d %d C%d %d %d %d %d %d', $pts);
            // номер — ближе к цели, чтобы веер потоков из одного узла не слипался у начала
            // (у цели с несколькими входящими — посередине, иначе номера сойдутся у цели)
            [$mx, $my] = self::at($pts, ($incoming[$f['to']] ?? 1) > 1 ? 0.5 : 0.78);
            $edges .= sprintf('<g class="dfd-flow"><path d="%s" marker-end="url(#dfd-arrow)"><title>%s</title></path><circle cx="%d" cy="%d" r="9"/><text x="%d" y="%d">%d</text></g>',
                $path, self::e($m->componentName($f['from']) . ' → ' . $m->componentName($f['to']) . ': ' . $f['description']), $mx, $my, $mx, $my + 4, $n);
        }
        $svg .= $edges;
        foreach ($nodes as $c) {
            [$x, $yy] = $pos[$c['id']];
            $svg .= self::node($c, $x, $yy);
        }
        return ['svg' => $svg . '</svg>', 'numbers' => $numbers];
    }

    /** @param array{id: string, name: string, type: string} $c */
    private static function node(array $c, int $x, int $y): string
    {
        $shape = match ($c['type']) {
            'datastore' => sprintf('<rect class="dfd-hit" x="%1$d" y="%2$d" width="%5$d" height="%6$d"/><path class="dfd-store" d="M%1$d %2$d H%3$d M%1$d %4$d H%3$d"/>', $x, $y, $x + self::W, $y + self::H, self::W, self::H),
            'process' => sprintf('<rect class="dfd-process" x="%d" y="%d" width="%d" height="%d" rx="14"/>', $x, $y, self::W, self::H),
            default => sprintf('<rect class="dfd-external" x="%d" y="%d" width="%d" height="%d"/>', $x, $y, self::W, self::H),
        };
        // «Имя (пояснение)» — в две строки
        [$name, $note] = array_pad(explode(' (', $c['name'], 2), 2, '');
        $note = rtrim($note, ')');
        $label = $note === ''
            ? sprintf('<text x="%d" y="%d">%s</text>', $x + self::W / 2, $y + 28, self::e(self::fit($name, 28)))
            : sprintf('<text x="%d" y="%d">%s</text><text class="dfd-note" x="%d" y="%d">%s</text>', $x + self::W / 2, $y + 20, self::e(self::fit($name, 28)), $x + self::W / 2, $y + 36, self::e(self::fit($note, 34)));
        return '<g class="dfd-node dfd-' . self::e($c['type']) . '"><title>' . self::e($c['name']) . '</title>' . $shape . $label . '</g>';
    }

    /**
     * Точка кубической кривой Безье при параметре t.
     * @param list<int|float> $p x0 y0 x1 y1 x2 y2 x3 y3
     * @return array{0: float, 1: float}
     */
    private static function at(array $p, float $t): array
    {
        $u = 1 - $t;
        $f = static fn (int $i) => $u ** 3 * $p[$i] + 3 * $u ** 2 * $t * $p[$i + 2] + 3 * $u * $t ** 2 * $p[$i + 4] + $t ** 3 * $p[$i + 6];
        return [$f(0), $f(1)];
    }

    private static function fit(string $s, int $max): string
    {
        return mb_strlen($s) > $max ? mb_substr($s, 0, $max - 1) . '…' : $s;
    }

    private static function e(string $s): string
    {
        return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE | ENT_XML1, 'UTF-8');
    }
}
