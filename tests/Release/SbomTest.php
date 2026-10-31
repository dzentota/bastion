<?php
declare(strict_types=1);

namespace Bastion\Tests\Release;

use Bastion\Release\Sbom;
use PHPUnit\Framework\TestCase;

/** Abuser stories: vendored-asset-tamper (подмена вендорных пакетов и шрифтов), threat-model-export-tamper (хэш экспорта в SBOM). */
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

    public function testVendoredFontsAreListedAndVerified(): void
    {
        $root = sys_get_temp_dir() . '/bastion-sbom-assets-' . bin2hex(random_bytes(4));
        mkdir($root . '/public/assets/fonts', 0777, true);
        file_put_contents($root . '/public/assets/fonts/a.woff2', 'wOF2 font');
        file_put_contents($root . '/public/assets/fonts/fonts.json', json_encode([[
            'purl' => 'pkg:npm/%40fontsource/x@1.0.0', 'group' => '@fontsource', 'name' => 'x', 'version' => '1.0.0',
            'license' => 'OFL-1.1', 'source' => 'https://example.invalid/', 'files' => ['a.woff2'],
        ]]));
        $sbom = Sbom::generate($this->lock, $this->vendor, '1.0.0', 0, $root);
        $font = array_values(array_filter($sbom['components'], static fn (array $c) => $c['name'] === 'x'))[0];
        self::assertSame('pkg:npm/%40fontsource/x@1.0.0', $font['purl']);
        self::assertSame([], Sbom::verify($sbom, $this->vendor, ['acme/lib', 'acme/branchy'], $root));

        file_put_contents($root . '/public/assets/fonts/a.woff2', 'tampered');
        self::assertStringContainsString('@fontsource/x: asset files differ', implode("\n", Sbom::verify($sbom, $this->vendor, [], $root)));
        unlink($root . '/public/assets/fonts/a.woff2');
        self::assertStringContainsString('@fontsource/x: asset files differ', implode("\n", Sbom::verify($sbom, $this->vendor, [], $root)));
    }

    public function testThreatModelExportHashIsRecordedAndVerified(): void
    {
        $root = sys_get_temp_dir() . '/bastion-sbom-tm-' . bin2hex(random_bytes(4));
        mkdir($root . '/build', 0777, true);
        mkdir($root . '/public/assets/fonts', 0777, true);
        file_put_contents($root . '/public/assets/fonts/fonts.json', '[]');
        file_put_contents($root . '/build/threat-model.json', '{"format":"bastion-threat-model"}');
        $sbom = Sbom::generate($this->lock, $this->vendor, '1.0.0', 0, $root);
        self::assertSame([], Sbom::verify($sbom, $this->vendor, ['acme/lib', 'acme/branchy'], $root));
        file_put_contents($root . '/build/threat-model.json', '{"format":"bastion-threat-model","all":"covered"}');
        self::assertStringContainsString('build/threat-model.json: differs', implode("\n", Sbom::verify($sbom, $this->vendor, [], $root)));
    }
}
