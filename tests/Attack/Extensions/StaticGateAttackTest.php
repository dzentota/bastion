<?php
declare(strict_types=1);

namespace Bastion\Tests\Attack\Extensions;

use Bastion\Extensions\Application\StaticGate;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** Abuser stories: malicious-extension, extension-static-gate-bypass, capability-overreach. */
final class StaticGateAttackTest extends TestCase
{
    private const NS = 'BastionExt\\Acme\\Hello';

    private function violations(string $body): array
    {
        $code = "<?php\ndeclare(strict_types=1);\nnamespace BastionExt\\Acme\\Hello;\n\nuse Bastion\\Extension\\Api\\{Context, Extension};\n\n" . $body;
        return (new StaticGate())->check(['src/Plugin.php' => $code], self::NS);
    }

    public function testCleanExtensionPasses(): void
    {
        $v = $this->violations(<<<'PHP'
            final class Plugin implements Extension
            {
                public function register(Context $context): void
                {
                    $context->helpers()->add('shout', static fn (string $s): string => mb_strtoupper(trim($s)) . '!');
                    $titles = array_map(static fn ($e) => $e->title, $context->content()->latest(5));
                    $context->helpers()->add('count', fn (string $s): string => (string) count($titles));
                }
            }
            PHP);
        self::assertSame([], array_map('strval', $v));
    }

    public static function bypasses(): iterable
    {
        yield 'system' => ['class P { public function x(): void { system("id"); } }'];
        yield 'fully qualified' => ['class P { public function x(): void { \\exec("id"); } }'];
        yield 'backticks' => ['class P { public function x(): string { return `id`; } }'];
        yield 'eval' => ['class P { public function x(): void { eval("phpinfo();"); } }'];
        yield 'include' => ['class P { public function x(): void { include "/etc/passwd"; } }'];
        yield 'require dynamic' => ['class P { public function x(string $f): void { require $f; } }'];
        yield 'string callable' => ['class P { public function x(): array { return array_map("system", ["id"]); } }'];
        yield 'variable function' => ['class P { public function x(): void { $f = "sys" . "tem"; $f("id"); } }'];
        yield 'callable via array_filter' => ['class P { public function x(): array { return array_filter(["id"], "passthru"); } }'];
        yield 'first-class callable' => ['class P { public function x(): \\Closure { return strlen(...); } }'];
        yield 'call_user_func' => ['class P { public function x(): void { call_user_func("system", "id"); } }'];
        yield 'variable variable' => ['class P { public function x(): void { $n = "GLOBALS"; $v = $$n; } }'];
        yield 'superglobal' => ['class P { public function x(): mixed { return $_SERVER["DOCUMENT_ROOT"]; } }'];
        yield 'GLOBALS' => ['class P { public function x(): mixed { return $GLOBALS; } }'];
        yield 'global statement' => ['class P { public function x(): void { global $db; } }'];
        yield 'file read' => ['class P { public function x(): string { return file_get_contents("../var/config.json"); } }'];
        yield 'network' => ['class P { public function x(): void { fsockopen("evil.example", 80); } }'];
        yield 'PDO' => ['class P { public function x(): void { new \\PDO("sqlite:/tmp/x"); } }'];
        yield 'reflection' => ['class P { public function x(object $o): void { (new \\ReflectionObject($o))->getProperties(); } }'];
        yield 'SplFileObject' => ['class P { public function x(): void { new \\SplFileObject("/etc/passwd"); } }'];
        yield 'core class' => ['class P { public function x(): void { \\Bastion\\Http\\Kernel::class; } }'];
        yield 'extend core' => ['class P extends \\Bastion\\Content\\Infrastructure\\EntryRepository {}'];
        yield 'dynamic new' => ['class P { public function x(string $c): object { return new $c(); } }'];
        yield 'dynamic method' => ['class P { public function x(object $o, string $m): void { $o->$m(); } }'];
        yield 'dynamic property' => ['class P { public function x(object $o): mixed { return $o->{"db"}; } }'];
        yield 'closure bind' => ['class P { public function x(object $facade): mixed { return \\Closure::bind(fn () => $this->db, $facade, $facade::class)(); } }'];
        yield 'bindTo' => ['class P { public function x(object $facade): void { $f = function () { return $this->db; }; $f->bindTo($facade, get_class($facade)); } }'];
        yield 'closure call' => ['class P { public function x(object $facade): void { (function () { return $this->db; })->call($facade); } }'];
        yield 'array cast leak' => ['class P { public function x(object $facade): array { return (array) $facade; } }'];
        yield 'exception trace' => ['class P { public function x(\\Closure $f): void { try { $f(); } catch (\\RuntimeException $e) { $e->getTrace(); } } }'];
        yield 'magic dir' => ['class P { public function x(): string { return __DIR__; } }'];
        yield 'echo' => ['class P { public function x(): void { echo "<script>alert(1)</script>"; } }'];
        yield 'inline html' => ['?><script>alert(1)</script><?php class P {}'];
        yield 'exit' => ['class P { public function x(): void { exit(1); } }'];
        yield 'top-level function' => ['function helper() {}'];
        yield 'unserialize' => ['class P { public function x(string $s): mixed { return unserialize($s); } }'];
        yield 'declare ticks' => ['declare(ticks=1); class P {}'];
        yield 'header' => ['class P { public function x(): void { header("Location: https://evil.example"); } }'];
        yield 'preg_replace_callback string' => ['class P { public function x(): string { return preg_replace_callback("/x/", "system", "x"); } }'];
        yield 'anonymous class extends core' => ['class P { public function x(): object { return new class extends \\Bastion\\Audit\\Infrastructure\\HmacAuditTrail {}; } }'];
    }

    #[DataProvider('bypasses')]
    public function testBypassIsRejected(string $body): void
    {
        self::assertNotSame([], $this->violations($body));
    }

    public function testWrongNamespaceIsRejected(): void
    {
        $v = (new StaticGate())->check(['a.php' => "<?php\nnamespace Bastion\\Http;\nfinal class Kernel {}"], self::NS);
        self::assertNotSame([], $v);
    }

    public function testCodeOutsideNamespaceIsRejected(): void
    {
        self::assertNotSame([], (new StaticGate())->check(['a.php' => "<?php\nfinal class X {}"], self::NS));
    }

    public function testUnparsableFileIsRejected(): void
    {
        self::assertNotSame([], (new StaticGate())->check(['a.php' => "<?php\nnamespace BastionExt\\Acme\\Hello; class {"], self::NS));
    }
}
