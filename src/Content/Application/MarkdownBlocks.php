<?php
declare(strict_types=1);

namespace Bastion\Content\Application;

use Bastion\Content\Domain\Block\{BlockList, Code, Heading, Paragraph, Quote, Table, ThreatModelEmbed};

/**
 * Подмножество Markdown из docs/adr → блоки: заголовки, абзацы, списки (абзац с «•»),
 * цитаты, блоки кода, таблицы, «::: threatmodel вид» — встроенная модель угроз. Строчная разметка снимается: `код`, **жирный**, [текст](url) → «текст (url)».
 * HTML в исходнике не интерпретируется — становится текстом, как любой ввод.
 */
final class MarkdownBlocks
{
    /** @return array{title: string, blocks: BlockList} */
    public static function parse(string $md): array
    {
        $lines = preg_split('/\r\n|\n|\r/', $md) ?: [];
        $title = '';
        $blocks = [];
        $para = [];
        $flush = static function () use (&$para, &$blocks): void {
            $text = trim(implode("\n", $para));
            if ($text !== '') {
                $blocks[] = Paragraph::fromArray(['text' => $text]);
            }
            $para = [];
        };
        for ($i = 0, $n = count($lines); $i < $n; $i++) {
            $line = $lines[$i];
            if (preg_match('/^```\s*([a-z]*)\s*$/', $line, $m)) {
                $flush();
                $code = [];
                for ($i++; $i < $n && !preg_match('/^```\s*$/', $lines[$i]); $i++) {
                    $code[] = $lines[$i];
                }
                if (trim(implode('', $code)) !== '') {
                    $blocks[] = Code::fromArray(['language' => in_array($m[1], Code::LANGUAGES, true) ? $m[1] : 'text', 'text' => implode("\n", $code)]);
                }
                continue;
            }
            if (preg_match('/^:::\s*threatmodel\s+([a-z]+)\s*$/', $line, $m)) {
                $flush();
                $blocks[] = ThreatModelEmbed::fromArray(['view' => $m[1]]);
                continue;
            }
            if (preg_match('/^(#{1,4})\s+(.+)$/', $line, $m)) {
                $flush();
                if ($m[1] === '#' && $title === '') {
                    $title = self::inline($m[2]);
                } else {
                    $blocks[] = Heading::fromArray(['text' => self::inline($m[2]), 'level' => 2]);
                }
                continue;
            }
            if (str_starts_with(ltrim($line), '|')) {
                $flush();
                $rows = [];
                for (; $i < $n && str_starts_with(ltrim($lines[$i]), '|'); $i++) {
                    if (!preg_match('/^\s*\|[\s:|-]+\|\s*$/', $lines[$i])) {
                        $rows[] = implode(' | ', array_map(static fn (string $c) => self::inline(trim($c)), explode('|', trim(trim($lines[$i]), '|'))));
                    }
                }
                $i--;
                $blocks[] = Table::fromArray(['text' => implode("\n", $rows), 'header' => true]);
                continue;
            }
            if (preg_match('/^>\s?(.*)$/', $line, $m)) {
                $flush();
                $quote = [self::inline($m[1])];
                for ($i++; $i < $n && preg_match('/^>\s?(.*)$/', $lines[$i], $q); $i++) {
                    $quote[] = self::inline($q[1]);
                }
                $i--;
                $blocks[] = Quote::fromArray(['text' => trim(implode("\n", $quote))]);
                continue;
            }
            if (trim($line) === '') {
                $flush();
                continue;
            }
            $para[] = preg_match('/^\s*(?:[-*]|\d+\.)\s+(.*)$/', $line, $m) ? '• ' . self::inline($m[1]) : self::inline(trim($line));
        }
        $flush();
        if ($title === '') {
            throw new \InvalidArgumentException('Markdown document has no "# title" line');
        }
        return ['title' => $title, 'blocks' => BlockList::of(...$blocks)];
    }

    private static function inline(string $s): string
    {
        $s = preg_replace('/\[([^\]]+)\]\(([^)\s]+)\)/u', '$1 ($2)', $s) ?? $s;
        $s = preg_replace('/(\*\*|__)(.+?)\1/u', '$2', $s) ?? $s;
        return str_replace('`', '', $s);
    }
}
