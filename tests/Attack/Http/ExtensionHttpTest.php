<?php
declare(strict_types=1);

namespace Bastion\Tests\Attack\Http;

use Bastion\IdentityAccess\Domain\{NewPassword, Role, Username};
use Bastion\IdentityAccess\Infrastructure\AccountRepository;
use Bastion\Infrastructure\Database\Connection;
use Bastion\Tests\Support\{ExtensionFixtures, HttpHarness};
use ParagonIE\Halite\KeyFactory;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

/** Админский поток расширений через HTTP: права, CSRF, отпечаток ключа, аудит. */
final class ExtensionHttpTest extends TestCase
{
    #[RunInSeparateProcess]
    public function testAdminInstallsReviewsAndEnables(): void
    {
        $h = new HttpHarness();
        $h->installAndLogin();
        $fx = new ExtensionFixtures();
        [$zip, $sig] = $fx->package(null, '1.0.0', ['render.helper']);

        $h->get('/admin/extensions');
        $res = $h->uploadMany('/admin/extensions', ['package' => [$zip, 'hello.zip'], 'signature' => [$sig, 'hello.zip.sig']]);
        self::assertSame(200, $res->getStatusCode());
        self::assertStringContainsString('Installed acme/hello 1.0.0', $h->body());
        self::assertStringContainsString('render.helper', $h->body());
        self::assertMatchesRegularExpression('/([0-9a-f]{4}:){15}[0-9a-f]{4}/', $h->body(), 'отпечаток ключа показан');
        self::assertStringContainsString('disabled', $h->body());

        self::assertSame(303, $h->post('/admin/extensions/enable', ['name' => 'acme/hello'])->getStatusCode());
        $h->get('/admin/extensions');
        self::assertStringContainsString('enabled', $h->body());
        self::assertSame(200, $h->fresh()->get('/en')->getStatusCode(), 'сайт работает с включённым расширением');

        $h->get('/admin/audit');
        self::assertStringContainsString('extension_installed', $h->body());
        self::assertStringContainsString('extension_enabled', $h->body());
    }

    public function testMaliciousUploadIsRejectedWithReason(): void
    {
        $h = new HttpHarness();
        $h->installAndLogin();
        $fx = new ExtensionFixtures();
        [$zip, $sig] = $fx->package(ExtensionFixtures::plugin('passthru("id");'));
        $h->get('/admin/extensions');
        self::assertSame(422, $h->uploadMany('/admin/extensions', ['package' => [$zip, 'x.zip'], 'signature' => [$sig, 'x.sig']])->getStatusCode());
        self::assertStringContainsString('passthru', $h->body());
        self::assertDirectoryDoesNotExist($h->paths->extensions() . '/acme');
    }

    public function testOnlyAdminsManageExtensionsAndCsrfIsRequired(): void
    {
        $h = new HttpHarness();
        $h->installAndLogin();
        $h->get('/admin');
        self::assertSame(403, $h->post('/admin/extensions/enable', ['name' => 'acme/hello'], withToken: false)->getStatusCode());

        $u = Username::fromNative('writer');
        (new AccountRepository(Connection::sqlite($h->paths->sqlite()), KeyFactory::loadEncryptionKey($h->paths->encryptionKey())))
            ->create($u, NewPassword::forUser('another long passphrase here', $u), Role::Editor);
        $editor = $h->fresh();
        $editor->get('/admin/login');
        $editor->post('/admin/login', ['username' => 'writer', 'password' => 'another long passphrase here']);
        $editor->get('/admin/2fa/setup');
        preg_match('~<code>([A-Z2-7 ]+)</code>~', $editor->body(), $m);
        $editor->post('/admin/2fa/setup', ['code' => \OTPHP\TOTP::createFromSecret(str_replace(' ', '', $m[1]))->now()]);
        self::assertSame(403, $editor->get('/admin/extensions')->getStatusCode(), 'редактор не управляет расширениями');
    }
}
