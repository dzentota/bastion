<?php
declare(strict_types=1);

namespace Bastion\Tests\Attack\Http;

use Bastion\Tests\Support\HttpHarness;
use PHPUnit\Framework\TestCase;

/** Abuser stories: hijack-installer, reinstall-over-live. */
final class InstallerAttackTest extends TestCase
{
    private const FORM = ['driver' => 'sqlite', 'username' => 'attacker', 'password' => 'correct horse battery staple', 'email' => 'attacker@example.com'];

    public function testAttackerWithoutFileAccessCannotInstall(): void
    {
        $h = new HttpHarness();
        $h->get('/install');
        self::assertSame(422, $h->post('/install', self::FORM + ['install_token' => str_repeat('0', 32)])->getStatusCode());
        self::assertFalse($h->paths->isInstalled());
    }

    public function testInstallRequiresCsrfToken(): void
    {
        $h = new HttpHarness();
        $h->get('/install');
        $token = trim((string) file_get_contents($h->paths->installToken()));
        self::assertSame(403, $h->post('/install', self::FORM + ['install_token' => $token], withToken: false)->getStatusCode());
    }

    public function testEverythingRedirectsToInstallerBeforeInstall(): void
    {
        $h = new HttpHarness();
        self::assertSame('/install', $h->get('/admin')->getHeaderLine('Location'));
    }

    public function testInstallerIsGoneAfterInstall(): void
    {
        $h = new HttpHarness();
        $h->installAndLogin();
        self::assertTrue($h->paths->isInstalled());
        self::assertFileDoesNotExist($h->paths->installToken());
        $attacker = $h->fresh();
        self::assertSame(404, $attacker->get('/install')->getStatusCode());
        self::assertSame(404, $attacker->post('/install', self::FORM + ['install_token' => 'x'], withToken: false)->getStatusCode());
    }

    /** Abuser story: storage-endpoint-ssrf — установщик не ходит на внутренние адреса. */
    public function testInstallerRejectsInternalStorageEndpoint(): void
    {
        $h = new HttpHarness();
        $h->get('/install');
        $token = trim((string) file_get_contents($h->paths->installToken()));
        $res = $h->post('/install', self::FORM + ['install_token' => $token, 's3_endpoint' => 'https://169.254.169.254',
            's3_bucket' => 'media', 's3_access_key' => 'AKIAIOSFODNN7EXAMPLE', 's3_secret_key' => 'wJalrXUtnFEMI/K7MDENG']);
        self::assertSame(422, $res->getStatusCode());
        self::assertStringContainsString('private, reserved', $h->body());
        self::assertStringNotContainsString('wJalrXUtnFEMI', $h->body(), 'секрет не отражается обратно в форму');
        self::assertFalse($h->paths->isInstalled());
    }
}
