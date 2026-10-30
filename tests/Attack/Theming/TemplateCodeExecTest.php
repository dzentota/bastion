<?php
declare(strict_types=1);

namespace Bastion\Tests\Attack\Theming;

use Bastion\Tests\Theming\Dsl\InMemorySource;
use Bastion\Theming\Dsl\{Renderer, TemplateName, TemplateSyntaxError};
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Abuser story: template-code-exec (threat-model/theming.php).
 * Как вредоносный издатель темы, я хочу выйти за пределы DSL, чтобы исполнить PHP.
 */
final class TemplateCodeExecTest extends TestCase
{
    private function render(string $tpl, array $ctx = []): string
    {
        return (new Renderer(new InMemorySource(['main' => $tpl])))->render(TemplateName::fromNative('main'), $ctx);
    }

    public function testPhpTagsInTemplateAreInertText(): void
    {
        $out = $this->render('<?php echo "pwned"; ?><?= 1+1 ?>');
        self::assertStringNotContainsString('pwned"; ?>2', $out);
        self::assertSame('<?php echo "pwned"; ?><?= 1+1 ?>', $out, 'текст выводится как есть, не исполняется');
    }

    public static function expressionInjections(): iterable
    {
        yield 'function call' => ['{{ system("id") }}'];
        yield 'method call' => ['{{ user.getPassword() }}'];
        yield 'php var' => ['{{ $_SERVER }}'];
        yield 'arithmetic' => ['{{ 7*7 }}'];
        yield 'string literal' => ['{{ "x" }}'];
        yield 'filter with args' => ['{{ a | attr("x") }}'];
        yield 'twig-style set' => ['{% set x = 1 %}'];
        yield 'include traversal' => ['{% include "../../config" %}'];
        yield 'include absolute' => ['{% include "/etc/passwd" %}'];
        yield 'include null byte' => ["{% include \"a\0b\" %}"];
        yield 'if expression' => ['{% if a == 1 %}x{% endif %}'];
    }

    #[DataProvider('expressionInjections')]
    public function testExpressionsAreRejectedAtParseTime(string $tpl): void
    {
        $this->expectException(TemplateSyntaxError::class);
        $this->render($tpl);
    }

    public function testObjectsInContextAreNotReachable(): void
    {
        $obj = new class { public string $secret = 'S3CRET'; public function secret(): string { return 'S3CRET'; } };
        self::assertSame('', $this->render('{{ o.secret }}', ['o' => $obj]));
    }

    public function testIncludeRecursionIsBounded(): void
    {
        $this->expectException(TemplateSyntaxError::class);
        (new Renderer(new InMemorySource(['main' => '{% include "main" %}'])))->render(TemplateName::fromNative('main'), []);
    }
}
