<?php
declare(strict_types=1);

namespace Bastion\Search\Domain;

use Bastion\Content\Domain\Block\{Block, BlockList, Callout, Code, Heading, Image, Paragraph, Quote, Table};

/** Текст записи для индекса: содержимое блоков без разметки. Встроенная модель угроз не индексируется. */
final class SearchText
{
    public const MAX_CHARS = 200_000;

    public static function of(BlockList $blocks): string
    {
        $parts = [];
        foreach ($blocks as $b) {
            if (!$b instanceof Block) {
                continue;
            }
            $parts[] = match (true) {
                $b instanceof Paragraph, $b instanceof Quote, $b instanceof Code, $b instanceof Callout => $b->text->toNative(),
                $b instanceof Heading => $b->text->toNative(),
                $b instanceof Table => str_replace(' | ', ' ', $b->text()),
                $b instanceof Image => $b->alt->toNative(),
                default => '',
            };
        }
        // маркеры подсветки не должны встречаться в индексируемом тексте
        $text = str_replace([SearchHit::MARK_OPEN, SearchHit::MARK_CLOSE], '', implode("\n", array_filter($parts)));
        return mb_substr($text, 0, self::MAX_CHARS);
    }
}
