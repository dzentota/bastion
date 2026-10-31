<?php
declare(strict_types=1);

namespace Bastion\Tests\Attack\Content;

use Bastion\Content\Domain\Block\{BlockList, Callout, Code, InvalidBlock, Table};
use Bastion\Content\Rendering\BlockHtmlRenderer;
use Bastion\Theming\Dsl\TrustedHtmlToken;
use PHPUnit\Framework\TestCase;

/** Блоки Code, Table, Callout. Abuser stories: stored-xss-block, trojan-source, table-bomb. */
final class RichBlocksTest extends TestCase
{
    private function render(array $blocks): string
    {
        return (new BlockHtmlRenderer(TrustedHtmlToken::forTesting()))->render(BlockList::fromJson(json_encode($blocks, JSON_THROW_ON_ERROR)))->toString();
    }

    public function testCodeIsEscapedVerbatimWithAllowlistedLanguage(): void
    {
        $html = $this->render([['type' => 'code', 'data' => ['language' => 'php', 'text' => "<?php\n\techo '</code><script>alert(1)</script>';"]]]);
        self::assertSame('<pre class="code"><code class="language-php">&lt;?php' . "\n\t" . 'echo &apos;&lt;/code&gt;&lt;script&gt;alert(1)&lt;/script&gt;&apos;;</code></pre>', $html);
        $this->expectException(InvalidBlock::class);
        Code::fromArray(['language' => 'php" onmouseover="x', 'text' => 'x']);
    }

    public function testBidiControlsAreRejected(): void
    {
        foreach (["\u{202E}", "\u{2066}", "\u{2069}", "\x00", "\x1B[31m"] as $c) {
            try {
                Code::fromArray(['language' => 'bash', 'text' => "rm -rf {$c}/tmp"]);
                self::fail('accepted ' . bin2hex($c));
            } catch (InvalidBlock) {
                self::addToAssertionCount(1);
            }
        }
    }

    public function testTableIsBoundedAndEscaped(): void
    {
        $html = $this->render([['type' => 'table', 'data' => ['header' => true, 'text' => "Name | Value\n<b>x</b> | 1"]]]);
        self::assertSame('<div class="table"><table><thead><tr><th>Name</th><th>Value</th></tr></thead><tbody><tr><td>&lt;b&gt;x&lt;/b&gt;</td><td>1</td></tr></tbody></table></div>', $html);
        foreach ([
            implode("\n", array_fill(0, Table::MAX_ROWS + 1, 'a')),
            implode(' | ', array_fill(0, Table::MAX_COLS + 1, 'a')),
            str_repeat('a', Table::MAX_CELL + 1),
            "\n \n",
        ] as $bad) {
            try {
                Table::fromArray(['text' => $bad]);
                self::fail('accepted oversized table');
            } catch (InvalidBlock) {
                self::addToAssertionCount(1);
            }
        }
    }

    public function testCalloutVariantIsAllowlisted(): void
    {
        self::assertSame("<aside class=\"callout callout-warning\" role=\"note\"><p>Back up first.<br>\nReally.</p></aside>",
            $this->render([['type' => 'callout', 'data' => ['variant' => 'warning', 'text' => "Back up first.\nReally."]]]));
        $this->expectException(InvalidBlock::class);
        Callout::fromArray(['variant' => 'x" style="', 'text' => 'x']);
    }
}
