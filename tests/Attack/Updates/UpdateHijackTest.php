<?php
declare(strict_types=1);

namespace Bastion\Tests\Attack\Updates;

use Bastion\Extensions\Application\{ExtensionInstaller, PackageReader, PackageSignature, StaticGate};
use Bastion\Extensions\Domain\{ExtensionName, PublisherKey};
use Bastion\Extensions\Infrastructure\ExtensionRegistry;
use Bastion\Tests\Support\{Database, ExtensionFixtures, FakeChronicle, RecordingAuditTrail};
use Bastion\Updates\Application\{ChronicleFeed, UpdateChannel, UpdateConfig};
use Bastion\Updates\Domain\{InvalidRecord, LedgerRecord};
use Bastion\Updates\Infrastructure\LedgerStore;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use SecureDb\Db;

/** Abuser story: update-hijack — подменённый релиз, украденный ключ, подмена журнала. */
final class UpdateHijackTest extends TestCase
{
    private Db $db;
    private string $key;
    private ExtensionFixtures $acme;
    private FakeChronicle $chronicle;
    private string $super;
    private UpdateChannel $channel;
    private ExtensionInstaller $installer;

    protected function setUp(): void
    {
        $this->db = Database::memory();
        $this->key = random_bytes(32);
        $this->acme = new ExtensionFixtures();
        $this->chronicle = new FakeChronicle();
        $this->super = sodium_crypto_sign_secretkey(sodium_crypto_sign_keypair());
        $this->channel = $this->channel();
        $dir = sys_get_temp_dir() . '/bastion-upd-' . bin2hex(random_bytes(4));
        mkdir($dir);
        $this->installer = new ExtensionInstaller(new PackageReader(), new StaticGate(), $this->registry(), $dir, new RecordingAuditTrail(), $this->channel);
    }

    private function registry(): ExtensionRegistry
    {
        return new ExtensionRegistry($this->db, $this->key);
    }

    private function channel(?string $chronicleKey = null): UpdateChannel
    {
        $cfg = new UpdateConfig('https://chronicle.test', PublisherKey::fromNative($chronicleKey ?? $this->chronicle->serverPublic), 'https://registry.test',
            PublisherKey::fromNative(base64_encode(sodium_crypto_sign_publickey_from_secretkey($this->super))));
        return new UpdateChannel($cfg, $this->chronicle, new LedgerStore($this->db, $this->key), $this->registry(), new RecordingAuditTrail(), new NullLogger());
    }

    private function record(array $r, string $secret): void
    {
        $this->chronicle->publish(LedgerRecord::sign($r, $secret));
    }

    /** @return array{0: string, 1: string} */
    private function released(ExtensionFixtures $by, string $version, bool $recordIt = true): array
    {
        $zip = ExtensionFixtures::zip(['extension.json' => $by->manifest($version), 'src/Plugin.php' => ExtensionFixtures::plugin()]);
        $sig = PackageSignature::sign($zip, $by->secret);
        if ($recordIt) {
            $this->record(['type' => 'release', 'publisher' => 'acme', 'package' => 'acme/hello', 'version' => $version,
                'digest' => bin2hex(PackageSignature::digest($zip))], $by->secret);
        }
        $this->chronicle->release('acme/hello', $version, $zip, $sig);
        return [$zip, $sig];
    }

    private function bootstrap(): void
    {
        $this->record(['type' => 'key-append', 'publisher' => 'acme', 'key' => $this->acme->public], $this->acme->secret);
        [$zip, $sig] = $this->released($this->acme, '1.0.0');
        $this->channel->sync();
        $this->installer->install($zip, $sig, 'admin', '198.51.100.1');
        $this->installer->enable(ExtensionName::fromNative('acme/hello'), 'admin', '198.51.100.1');
    }

    private function version(): string
    {
        return (string) $this->registry()->find(ExtensionName::fromNative('acme/hello'))?->manifest->version->toNative();
    }

    public function testLegitimateUpdateIsInstalled(): void
    {
        $this->bootstrap();
        $this->released($this->acme, '1.1.0');
        $this->channel->sync();
        $report = $this->channel->run($this->installer);
        self::assertSame('1.1.0', $this->version(), implode("\n", $report));
    }

    public function testTamperedReleaseFromCompromisedRegistryIsRejected(): void
    {
        $this->bootstrap();
        $this->released($this->acme, '1.1.0');
        // реестр взломан: архив другой, но подписан настоящим (украденным) ключом — digest не совпадёт
        $evil = ExtensionFixtures::zip(['extension.json' => $this->acme->manifest('1.1.0'), 'src/Plugin.php' => ExtensionFixtures::plugin("\$context->helpers()->add('x', static fn (string \$s): string => \$s . 'pwn');")]);
        $this->chronicle->release('acme/hello', '1.1.0', $evil, PackageSignature::sign($evil, $this->acme->secret));
        $this->channel->sync();
        $report = implode("\n", $this->channel->run($this->installer));
        self::assertSame('1.0.0', $this->version());
        self::assertStringContainsString('digest differs', $report);
    }

    public function testSignedButUnrecordedReleaseIsRejected(): void
    {
        $this->bootstrap();
        $this->released($this->acme, '2.0.0', recordIt: false);
        $this->channel->sync();
        self::assertStringContainsString('not recorded', implode("\n", $this->channel->run($this->installer)));
        self::assertSame('1.0.0', $this->version());
    }

    public function testStolenKeyRevokedBySuperProviderDisablesAndBlocks(): void
    {
        $this->bootstrap();
        $this->record(['type' => 'key-revoke', 'publisher' => 'acme', 'key' => $this->acme->public], $this->super);
        $this->released($this->acme, '1.1.0'); // вор публикует релиз уже отозванным ключом
        $this->channel->sync();
        self::assertFalse($this->registry()->find(ExtensionName::fromNative('acme/hello'))?->enabled, 'расширение отозванного ключа выключено');
        $this->channel->run($this->installer);
        self::assertSame('1.0.0', $this->version());
    }

    public function testKeyRotationViaLedgerIsAcceptedButForeignKeyIsNot(): void
    {
        $this->bootstrap();
        $next = new ExtensionFixtures();
        $this->record(['type' => 'key-append', 'publisher' => 'acme', 'key' => $next->public], $this->acme->secret);
        $this->released($next, '1.1.0');
        $this->channel->sync();
        $this->channel->run($this->installer);
        self::assertSame('1.1.0', $this->version(), 'ротация, подписанная старым ключом');

        $attacker = new ExtensionFixtures();
        // самоподписанный key-append для существующего издателя игнорируется
        $this->record(['type' => 'key-append', 'publisher' => 'acme', 'key' => $attacker->public], $attacker->secret);
        $this->released($attacker, '1.2.0');
        $this->channel->sync();
        $this->channel->run($this->installer);
        self::assertSame('1.1.0', $this->version());
    }

    public function testBootstrapOfForeignKeyIsNotRotationForExtensionPinnedOutsideLedger(): void
    {
        // расширение поставлено до настройки канала: его ключа в журнале нет
        $zip = ExtensionFixtures::zip(['extension.json' => $this->acme->manifest('1.0.0'), 'src/Plugin.php' => ExtensionFixtures::plugin()]);
        (new ExtensionInstaller(new PackageReader(), new StaticGate(), $this->registry(), sys_get_temp_dir() . '/bastion-upd-' . bin2hex(random_bytes(4)), new RecordingAuditTrail()))
            ->install($zip, PackageSignature::sign($zip, $this->acme->secret), 'admin', '198.51.100.1');
        $attacker = new ExtensionFixtures();
        $this->record(['type' => 'key-append', 'publisher' => 'acme', 'key' => $attacker->public], $attacker->secret);
        $this->released($attacker, '1.1.0');
        $this->channel->sync();
        self::assertStringContainsString('pinned', implode("\n", $this->channel->run($this->installer)));
        self::assertSame('1.0.0', $this->version());
    }

    public function testRewrittenForkedOrForgedChronicleIsRefused(): void
    {
        $this->bootstrap();
        $head = $this->chronicle->entries;

        // форк: сервер отдаёт альтернативную историю, где у acme другой первый ключ
        $this->chronicle->entries = [];
        $attacker = new ExtensionFixtures();
        $this->record(['type' => 'key-append', 'publisher' => 'acme', 'key' => $attacker->public], $attacker->secret);
        $this->released($attacker, '9.0.0');
        try {
            $this->channel->sync();
            self::fail('forked history accepted');
        } catch (InvalidRecord $e) {
            self::assertStringContainsString('chain', $e->getMessage());
        }

        // ответ подписан не тем ключом сервера (MITM)
        $this->chronicle->entries = $head;
        try {
            $this->channel(base64_encode(sodium_crypto_sign_publickey(sodium_crypto_sign_keypair())))->sync();
            self::fail('forged response accepted');
        } catch (InvalidRecord $e) {
            self::assertStringContainsString('signature', $e->getMessage());
        }
    }

    public function testLocalLedgerTamperingIsDetected(): void
    {
        $this->bootstrap();
        $this->db->query('UPDATE ?_ledger SET contents = ? WHERE seq = 2', '{"x":1}');
        $this->expectException(InvalidRecord::class);
        (new LedgerStore($this->db, $this->key))->contents();
    }
}
