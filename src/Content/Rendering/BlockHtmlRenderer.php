<?php
declare(strict_types=1);

namespace Bastion\Content\Rendering;

use Bastion\Content\Domain\Block\{Block, BlockList, Callout, Code, Heading, Image, Paragraph, Quote, Table};
use Bastion\Theming\Dsl\{SafeHtml, TrustedHtmlToken};
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};

/**
 * Единственное место, где из блоков строится HTML (правило 1: Lord of the Sinks).
 * Весь пользовательский текст экранируется; разметку задаёт только этот класс.
 */
#[AbuserStory('stored-xss-block')]
#[Mitigation(cwe: 'CWE-79', description: 'Blocks are typed values without HTML; markup is produced only here and all text is escaped')]
#[AssetId('bastion-app')]
final class BlockHtmlRenderer
{
    public function __construct(private readonly TrustedHtmlToken $token)
    {
    }

    public function render(BlockList $blocks): SafeHtml
    {
        $html = '';
        $n = 0;
        foreach ($blocks as $block) {
            $html .= $block instanceof Heading
                ? sprintf('<h%1$d id="s%3$d">%2$s</h%1$d>', $block->level, $this->esc($block->text->toNative()), ++$n)
                : $this->block($block);
        }
        return new SafeHtml($html, $this->token);
    }

    /**
     * Оглавление «На этой странице»: те же якоря, что ставит render() (s1, s2, … по порядку).
     * @return list<array{id: string, text: string}>
     */
    public static function outline(BlockList $blocks): array
    {
        $out = [];
        foreach ($blocks as $block) {
            if ($block instanceof Heading) {
                $out[] = ['id' => 's' . (count($out) + 1), 'text' => $block->text->toNative()];
            }
        }
        return $out;
    }

    private function block(Block $block): string
    {
        return match (true) {
            $block instanceof Paragraph => '<p>' . $this->text($block->text->toNative()) . '</p>',
            $block instanceof Heading => sprintf('<h%1$d>%2$s</h%1$d>', $block->level, $this->esc($block->text->toNative())),
            $block instanceof Image => sprintf(
                '<figure><img src="/media/%s" alt="%s" loading="lazy" decoding="async"></figure>',
                $block->media->toNative(), // 32 hex — безопасен в атрибуте по построению
                $this->esc($block->alt->toNative()),
            ),
            $block instanceof Quote => '<blockquote><p>' . $this->text($block->text->toNative()) . '</p></blockquote>',
            // язык и вариант — из закрытых списков, безопасны в атрибуте по построению
            $block instanceof Code => sprintf('<pre class="code"><code class="language-%s">%s</code></pre>', $block->language, $this->esc($block->text->toNative())),
            $block instanceof Callout => sprintf('<aside class="callout callout-%s" role="note"><p>%s</p></aside>', $block->variant, $this->text($block->text->toNative())),
            $block instanceof Table => $this->table($block),
            default => throw new \LogicException('Unrenderable block ' . $block::type()),
        };
    }

    private function table(Table $t): string
    {
        $rows = $t->rows;
        $head = $t->header ? array_shift($rows) : null;
        $body = '';
        foreach ($rows as $r) {
            $body .= $this->row($r, 'td');
        }
        return '<div class="table"><table>'
            . ($head !== null ? '<thead>' . $this->row($head, 'th') . '</thead>' : '')
            . '<tbody>' . $body . '</tbody></table></div>';
    }

    /** @param list<string> $cells */
    private function row(array $cells, string $tag): string
    {
        $html = '<tr>';
        foreach ($cells as $c) {
            $html .= "<{$tag}>" . $this->esc($c) . "</{$tag}>";
        }
        return $html . '</tr>';
    }

    private function text(string $s): string
    {
        return nl2br($this->esc($s), false);
    }

    private function esc(string $s): string
    {
        return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
    }
}
