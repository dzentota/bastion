<?php
declare(strict_types=1);

namespace Bastion\Content\Rendering;

use Bastion\Content\Domain\Block\{Block, BlockList, Heading, Paragraph, Quote};
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
        foreach ($blocks as $block) {
            $html .= $this->block($block);
        }
        return new SafeHtml($html, $this->token);
    }

    private function block(Block $block): string
    {
        return match (true) {
            $block instanceof Paragraph => '<p>' . $this->text($block->text->toNative()) . '</p>',
            $block instanceof Heading => sprintf('<h%1$d>%2$s</h%1$d>', $block->level, $this->esc($block->text->toNative())),
            $block instanceof Quote => '<blockquote><p>' . $this->text($block->text->toNative()) . '</p></blockquote>',
            default => throw new \LogicException('Unrenderable block ' . $block::type()),
        };
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
