<?php
declare(strict_types=1);

namespace Bastion\Tests\Attack\Content;

use Bastion\Content\Domain\Block\BlockList;
use Bastion\Content\Rendering\BlockHtmlRenderer;
use Bastion\Theming\Dsl\TrustedHtmlToken;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Abuser story: stored-xss-block (threat-model/content.php).
 * Как злонамеренный автор, я хочу сохранить разметку, исполняемую в браузере читателя или админа.
 */
final class StoredXssBlockTest extends TestCase
{
    public static function payloads(): iterable
    {
        yield ['<script>alert(1)</script>'];
        yield ['<img src=x onerror=alert(1)>'];
        yield ['"><svg/onload=alert(1)>'];
        yield ['<a href="javascript:alert(1)">x</a>'];
        yield ["</p><iframe src=//evil>"];
    }

    #[DataProvider('payloads')]
    public function testPayloadInEveryBlockTypeIsInert(string $payload): void
    {
        $p = json_encode($payload);
        $blocks = BlockList::fromJson("[{\"type\":\"paragraph\",\"data\":{\"text\":$p}},"
            . "{\"type\":\"quote\",\"data\":{\"text\":$p}},"
            . "{\"type\":\"heading\",\"data\":{\"level\":3,\"text\":$p}}]");
        $html = (new BlockHtmlRenderer(TrustedHtmlToken::forTesting()))->render($blocks)->toString();

        self::assertDoesNotMatchRegularExpression('/<(script|img|svg|a|iframe)\b/i', $html);
        self::assertStringNotContainsString('"', strip_tags($html), 'кавычки экранированы');
    }

    public function testRawHtmlBlockTypeDoesNotExist(): void
    {
        $this->expectException(\Bastion\Content\Domain\Block\InvalidBlock::class);
        BlockList::fromJson('[{"type":"html","data":{"html":"<script>"}}]');
    }
}
