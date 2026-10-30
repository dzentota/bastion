<?php
declare(strict_types=1);

namespace Bastion\Tests\Theming\Dsl;

use Bastion\Theming\Dsl\{Renderer, SafeHtml, TemplateName, TemplateSyntaxError, TrustedHtmlToken};
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class RendererTest extends TestCase
{
    private function render(string $tpl, array $ctx = [], array $more = [], array $helpers = []): string
    {
        $r = new Renderer(new InMemorySource(['main' => $tpl] + $more), null, $helpers);
        return $r->render(TemplateName::fromNative('main'), $ctx);
    }

    public function testOutputsNestedValues(): void
    {
        self::assertSame('Hi Ann!', $this->render('Hi {{ user.name }}!', ['user' => ['name' => 'Ann']]));
    }

    public function testMissingValueRendersEmpty(): void
    {
        self::assertSame('[]', $this->render('[{{ nope.deep }}]'));
    }

    public function testIfElse(): void
    {
        $tpl = '{% if a %}A{% else %}B{% endif %}{% if not a %}C{% endif %}';
        self::assertSame('A', $this->render($tpl, ['a' => true]));
        self::assertSame('BC', $this->render($tpl, ['a' => '']));
    }

    public function testEachWithNestedIf(): void
    {
        $tpl = '{% each posts as p %}<{{ p.title }}{% if p.draft %}*{% endif %}>{% endeach %}';
        self::assertSame('&lt;a*&gt;&lt;b&gt;', $this->render(
            '{% each posts as p %}{{ p.title }}{% endeach %}',
            ['posts' => [['title' => '<a*>'], ['title' => '<b>']]],
        ));
        self::assertSame('<a*><b>', $this->render($tpl, ['posts' => [['title' => 'a', 'draft' => true], ['title' => 'b']]]));
    }

    public function testInclude(): void
    {
        self::assertSame('[x]', $this->render('[{% include "part/x" %}]', ['v' => 'x'], ['part/x' => '{{ v }}']));
    }

    public function testSafeHtmlIsNotEscaped(): void
    {
        $html = new SafeHtml('<p>ok</p>', TrustedHtmlToken::forTesting());
        self::assertSame('<p>ok</p>', $this->render('{{ body }}', ['body' => $html]));
    }

    public function testHelperOutputIsEscaped(): void
    {
        $out = $this->render('{{ t | shout }}', ['t' => 'hi'], [], ['shout' => fn (string $s) => "<b>{$s}</b>"]);
        self::assertSame('&lt;b&gt;hi&lt;/b&gt;', $out);
    }

    public static function syntaxErrors(): iterable
    {
        yield 'unclosed if' => ['{% if a %}x'];
        yield 'stray endif' => ['x{% endif %}'];
        yield 'double else' => ['{% if a %}{% else %}{% else %}{% endif %}'];
        yield 'unknown filter' => ['{{ a | upper }}'];
        yield 'unbalanced' => ['{{ a'];
        yield 'mismatched' => ['{% each a as b %}{% endif %}'];
    }

    #[DataProvider('syntaxErrors')]
    public function testSyntaxErrors(string $tpl): void
    {
        $this->expectException(TemplateSyntaxError::class);
        $this->render($tpl);
    }
}
