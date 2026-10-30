<?php
declare(strict_types=1);

namespace Bastion\Tests\Attack\Theming;

use Bastion\Tests\Theming\Dsl\InMemorySource;
use Bastion\Theming\Dsl\{Renderer, TemplateName};
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** Abuser stories: stored-xss-block, comment-xss — вывод данных через тему. */
final class TemplateXssTest extends TestCase
{
    private function render(string $tpl, array $ctx): string
    {
        return (new Renderer(new InMemorySource(['main' => $tpl])))->render(TemplateName::fromNative('main'), $ctx);
    }

    public function testHtmlContextEscapes(): void
    {
        $out = $this->render('<p>{{ c }}</p>', ['c' => '<script>alert(1)</script>']);
        self::assertStringNotContainsString('<script>', $out);
    }

    public function testAttrContextCannotBreakOut(): void
    {
        $out = $this->render('<a title="{{ c | attr }}">', ['c' => '" onmouseover="alert(1)']);
        self::assertStringNotContainsString('" onmouseover', $out);
    }

    public static function dangerousUrls(): iterable
    {
        yield ['javascript:alert(1)'];
        yield ['JaVaScRiPt:alert(1)'];
        yield [' javascript:alert(1)'];
        yield ['data:text/html,<script>alert(1)</script>'];
        yield ['//evil.example/x'];
        yield ['vbscript:x'];
    }

    #[DataProvider('dangerousUrls')]
    public function testUrlFilterNeutralisesDangerousSchemes(string $url): void
    {
        self::assertSame('<a href="#">', $this->render('<a href="{{ u | url }}">', ['u' => $url]));
    }

    public function testUrlFilterKeepsSafeUrls(): void
    {
        $out = $this->render('<a href="{{ u | url }}">', ['u' => 'https://example.com/a?b=1&c=2']);
        self::assertStringStartsWith('<a href="https://example.com/a?b=1', $out);
        self::assertStringNotContainsString('&c=', $out, 'амперсанд должен быть экранирован');
    }
}
