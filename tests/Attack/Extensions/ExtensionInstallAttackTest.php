<?php
declare(strict_types=1);

namespace Bastion\Tests\Attack\Extensions;

use Bastion\Extensions\Application\{ExtensionInstaller, ExtensionLoader, HelperCollector, PackageReader, PackageSignature, StaticGate};
use Bastion\Extensions\Domain\{ExtensionName, InvalidPackage};
use Bastion\Extensions\Infrastructure\ExtensionRegistry;
use Bastion\Extension\Api\{ContentReader, PublishedEntry};
use Bastion\SecurityMonitoring\Infrastructure\DbAppSensor;
use Bastion\Tests\Support\{Database, ExtensionFixtures, FrozenClock, RecordingAuditTrail};
use PHPUnit\Framework\Attributes\{DataProvider, RunInSeparateProcess};
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use SecureDb\Db;

/**
 * Abuser stories: extension-zip-slip, extension-archive-bomb, extension-key-substitution,
 * extension-disk-tamper, capability-overreach, malicious-extension.
 */
final class ExtensionInstallAttackTest extends TestCase
{
    private Db $db;
    private string $dir;
    private string $key;
    private ExtensionFixtures $fx;
    private ExtensionInstaller $installer;

    protected function setUp(): void
    {
        $this->db = Database::memory();
        $this->dir = sys_get_temp_dir() . '/bastion-ext-' . bin2hex(random_bytes(4));
        mkdir($this->dir);
        $this->key = random_bytes(32);
        $this->fx = new ExtensionFixtures();
        $this->installer = new ExtensionInstaller(new PackageReader(), new StaticGate(), $this->registry(), $this->dir, new RecordingAuditTrail());
    }

    private function registry(): ExtensionRegistry
    {
        return new ExtensionRegistry($this->db, $this->key);
    }

    private function loader(HelperCollector $helpers): ExtensionLoader
    {
        $content = new class implements ContentReader {
            public function latest(int $limit): array
            {
                return [new PublishedEntry('Hello', '/hello', '2026-10-30')];
            }
        };
        return new ExtensionLoader($this->registry(), $this->installer, $helpers, $content,
            new DbAppSensor($this->db, new FrozenClock(), new NullLogger()), new NullLogger());
    }

    private function rejects(string $zip, string $sig, string $fragment = ''): void
    {
        try {
            $this->installer->install($zip, $sig, 'admin', '198.51.100.1');
            self::fail('Package was accepted');
        } catch (InvalidPackage $e) {
            self::assertStringContainsString($fragment, $e->getMessage());
        }
    }

    #[RunInSeparateProcess]
    public function testSignedCleanExtensionInstallsDisabledThenRuns(): void
    {
        [$zip, $sig] = $this->fx->package();
        $ext = $this->installer->install($zip, $sig, 'admin', '198.51.100.1');
        self::assertFalse($ext->enabled, 'новое расширение выключено до решения админа');

        $helpers = new HelperCollector(new NullLogger());
        self::assertSame([], $this->loader($helpers)->loadEnabled());

        $this->installer->enable(ExtensionName::fromNative('acme/hello'), 'admin', '198.51.100.1');
        self::assertSame(['acme/hello'], $this->loader($helpers)->loadEnabled());
        self::assertSame('HI!', ($helpers->all()['acme_hello_shout'])('hi'));
    }

    public function testUnsignedOrWronglySignedPackageIsRejected(): void
    {
        [$zip] = $this->fx->package();
        $this->rejects($zip, '', 'Signature');
        $other = new ExtensionFixtures();
        $this->rejects($zip, PackageSignature::sign($zip, $other->secret), 'Signature');
        $this->rejects($zip . "\0", PackageSignature::sign($zip, $this->fx->secret));
    }

    public function testNewVersionWithDifferentKeyIsRefused(): void
    {
        [$zip, $sig] = $this->fx->package();
        $this->installer->install($zip, $sig, 'admin', 'x');
        $attacker = new ExtensionFixtures();
        [$evil, $evilSig] = $attacker->package(null, '2.0.0');
        $this->rejects($evil, $evilSig, 'pinned');
    }

    public function testDowngradeIsRefused(): void
    {
        [$zip, $sig] = $this->fx->package(null, '2.0.0');
        $this->installer->install($zip, $sig, 'admin', 'x');
        [$old, $oldSig] = $this->fx->package(null, '1.0.0');
        $this->rejects($old, $oldSig, 'newer');
    }

    public function testMaliciousCodeIsRejectedByStaticGate(): void
    {
        [$zip, $sig] = $this->fx->package(ExtensionFixtures::plugin('shell_exec("id");'));
        $this->rejects($zip, $sig, 'Static Gate');
        self::assertSame([], glob($this->dir . '/*/*/*') ?: [], 'ничего не записано на диск');
    }

    public static function evilArchives(): iterable
    {
        yield 'zip slip' => [['extension.json' => '{}', '../../public/shell.php' => '<?php']];
        yield 'absolute path' => [['extension.json' => '{}', '/tmp/x.php' => '<?php']];
        yield 'backslash' => [['extension.json' => '{}', 'src\\..\\x.php' => '<?php']];
        yield 'hidden file' => [['extension.json' => '{}', 'src/.htaccess' => 'x']];
        yield 'php outside src' => [['extension.json' => '{}', 'shell.php' => '<?php']];
        yield 'phar' => [['extension.json' => '{}', 'src/X.phar' => 'x']];
    }

    #[DataProvider('evilArchives')]
    public function testDangerousArchiveEntriesAreRejected(array $files): void
    {
        $zip = ExtensionFixtures::zip($files);
        $this->rejects($zip, PackageSignature::sign($zip, $this->fx->secret), 'Disallowed entry');
    }

    public function testArchiveBombIsRejected(): void
    {
        $zip = ExtensionFixtures::zip(['extension.json' => $this->fx->manifest(), 'src/Plugin.php' => str_repeat(' ', 3 * 1024 * 1024)]);
        $this->rejects($zip, PackageSignature::sign($zip, $this->fx->secret), 'too large');
        $many = [];
        for ($i = 0; $i < 250; $i++) {
            $many["src/C{$i}.php"] = '<?php';
        }
        $zip = ExtensionFixtures::zip($many);
        $this->rejects($zip, PackageSignature::sign($zip, $this->fx->secret), 'entries');
    }

    #[RunInSeparateProcess]
    public function testFileEditedOnDiskIsNotExecuted(): void
    {
        [$zip, $sig] = $this->fx->package();
        $this->installer->install($zip, $sig, 'admin', 'x');
        $this->installer->enable(ExtensionName::fromNative('acme/hello'), 'admin', 'x');
        $file = $this->dir . '/acme/hello/1.0.0/src/Plugin.php';
        file_put_contents($file, str_replace("mb_strtoupper(\$s) . '!'", 'shell_exec($s)', (string) file_get_contents($file)));

        $helpers = new HelperCollector(new NullLogger());
        self::assertSame([], $this->loader($helpers)->loadEnabled());
        self::assertSame([], $helpers->all());
    }

    #[RunInSeparateProcess]
    public function testDatabaseOnlyAttackerCannotEnableOrGrant(): void
    {
        [$zip, $sig] = $this->fx->package();
        $this->installer->install($zip, $sig, 'admin', 'x');
        $this->db->query("UPDATE ?_extensions SET enabled = 1, granted = '[\"render.helper\",\"content.read\"]'");
        self::assertSame([], $this->loader(new HelperCollector(new NullLogger()))->loadEnabled());
    }

    #[RunInSeparateProcess]
    public function testUngrantedCapabilityIsDenied(): void
    {
        $body = "\$context->content()->latest(1);";
        [$zip, $sig] = $this->fx->package(ExtensionFixtures::plugin($body), '1.0.0', ['render.helper']);
        $this->installer->install($zip, $sig, 'admin', 'x');
        $this->installer->enable(ExtensionName::fromNative('acme/hello'), 'admin', 'x');
        // content.read не запрошен и не выдан → register() бросает CapabilityNotGranted → расширение не загружено
        self::assertSame([], $this->loader(new HelperCollector(new NullLogger()))->loadEnabled());
    }

    public function testUpdateRequestingNewCapabilitiesComesBackDisabled(): void
    {
        [$zip, $sig] = $this->fx->package();
        $this->installer->install($zip, $sig, 'admin', 'x');
        $this->installer->enable(ExtensionName::fromNative('acme/hello'), 'admin', 'x');
        [$v2, $v2sig] = $this->fx->package(null, '1.1.0', ['render.helper', 'content.read']);
        self::assertFalse($this->installer->install($v2, $v2sig, 'admin', 'x')->enabled);
        [$v3, $v3sig] = $this->fx->package(null, '1.2.0', ['render.helper']);
        $this->installer->enable(ExtensionName::fromNative('acme/hello'), 'admin', 'x');
        self::assertTrue($this->installer->install($v3, $v3sig, 'admin', 'x')->enabled, 'патч без новых прав остаётся включённым');
    }
}
