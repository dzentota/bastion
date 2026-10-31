<?php
declare(strict_types=1);

namespace Bastion\Tests\Release;

use Bastion\Release\Sbom;
use PHPUnit\Framework\TestCase;

final class SbomTest extends TestCase
{
    private string $vendor;
    /** @var array<string, mixed> */
    private array $lock;

    protected function setUp(): void
    {
        $this->vendor = sys_get_temp_dir() . '/bastion-sbom-' . bin2hex(random_bytes(4));
        foreach (['acme/lib' => 'A', 'acme/branchy' => 'B'] as $name => $code) {
            mkdir("{$this->vendor}/{$name}/src", 0777, true);
            file_put_contents("{$this->vendor}/{$name}/src/X.php", "<?php // {$code}\n");
        }
        $this->lock = ['content-hash' => 'abc', 'packages' => [
            ['name' => 'acme/lib', 'version' => '1.2.3', 'license' => ['MIT'], 'require' => ['php' => '>=8.3', 'acme/branchy' => 'dev-main'],
                'source' => ['type' => 'git', 'url' => 'https://example.com/lib.git', 'reference' => 'deadbeef']],
            ['name' => 'acme/branchy', 'version' => 'dev-main', 'license' => ['GPL-2.0-or-later'],
                'source' => ['type' => 'git', 'url' => 'https://example.com/b.git', 'reference' => 'cafe']],
        ]];
    }

    public function testCycloneDxShapeAndDeterminism(): void
    {
        $a = Sbom::generate($this->lock, $this->vendor, '1.0.0', 1_800_000_000);
        self::assertSame($a, Sbom::generate($this->lock, $this->vendor, '1.0.0', 1_800_000_000), 'воспроизводимо');
        self::assertSame('CycloneDX', $a['bomFormat']);
        self::assertSame('1.5', $a['specVersion']);
        self::assertMatchesRegularExpression('/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/', $a['serialNumber']);
        $lib = $a['components'][0];
        self::assertSame('pkg:composer/acme/lib@1.2.3', $lib['purl']);
        self::assertSame([['license' => ['id' => 'MIT']]], $lib['licenses']);
        self::assertSame('SHA-256', $lib['hashes'][0]['alg']);
        self::assertContains(['ref' => 'pkg:composer/acme/lib@1.2.3', 'dependsOn' => ['pkg:composer/acme/branchy@dev-main']], $a['dependencies']);
        self::assertContains(['name' => 'bastion:unpinned-branch', 'value' => 'true'], $a['components'][1]['properties']);
        self::assertContains(['name' => 'bastion:vcs-reference', 'value' => 'cafe'], $a['components'][1]['properties']);
    }

    public function testVerifyDetectsModifiedMissingAndExtraPackages(): void
    {
        $sbom = Sbom::generate($this->lock, $this->vendor, '1.0.0', 0);
        self::assertSame([], Sbom::verify($sbom, $this->vendor, ['acme/lib', 'acme/branchy']));

        file_put_contents("{$this->vendor}/acme/lib/src/X.php", "<?php eval(\$_GET['x']);\n");
        file_put_contents("{$this->vendor}/acme/branchy/src/Backdoor.php", "<?php\n");
        mkdir("{$this->vendor}/evil/pkg", 0777, true);
        $problems = implode("\n", Sbom::verify($sbom, $this->vendor, ['acme/lib', 'acme/branchy', 'evil/pkg']));
        self::assertStringContainsString('acme/lib: files differ', $problems);
        self::assertStringContainsString('acme/branchy: files differ', $problems, 'добавленный файл тоже заметен');
        self::assertStringContainsString('evil/pkg: installed but not in SBOM', $problems);

        exec('rm -rf ' . escapeshellarg("{$this->vendor}/acme/lib"));
        self::assertStringContainsString('acme/lib: missing', implode("\n", Sbom::verify($sbom, $this->vendor, [])));
    }
}
