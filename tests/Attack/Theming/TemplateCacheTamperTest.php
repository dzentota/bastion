<?php
declare(strict_types=1);

namespace Bastion\Tests\Attack\Theming;

use Bastion\Tests\Theming\Dsl\InMemorySource;
use Bastion\Theming\Dsl\{CacheTampered, Renderer, SignedAstCache, TemplateName};
use PHPUnit\Framework\TestCase;

/** Abuser story: template-cache-tamper. */
final class TemplateCacheTamperTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/bastion-cache-' . bin2hex(random_bytes(4));
        mkdir($this->dir);
    }

    protected function tearDown(): void
    {
        array_map('unlink', glob($this->dir . '/*') ?: []);
        rmdir($this->dir);
    }

    public function testTamperedCacheIsRejected(): void
    {
        $key = random_bytes(32);
        $renderer = new Renderer(new InMemorySource(['main' => '{{ x }}']), new SignedAstCache($this->dir, $key));
        $name = TemplateName::fromNative('main');
        self::assertSame('&lt;', $renderer->render($name, ['x' => '<']));

        // атакующий с правом записи подменяет AST: вывод без экранирования
        $file = glob($this->dir . '/*.ast')[0];
        $raw = file_get_contents($file);
        $forged = str_replace('"t":"out"', '"t":"text","v":"<script>"', substr($raw, 64));
        file_put_contents($file, substr($raw, 0, 64) . $forged);

        $this->expectException(CacheTampered::class);
        $renderer->render($name, ['x' => '<']);
    }

    public function testCacheIsDataNotCode(): void
    {
        $renderer = new Renderer(new InMemorySource(['main' => 'hi']), new SignedAstCache($this->dir, random_bytes(32)));
        $renderer->render(TemplateName::fromNative('main'), []);
        $raw = file_get_contents(glob($this->dir . '/*.ast')[0]);
        self::assertStringNotContainsString('<?php', $raw);
    }
}
