<?php
declare(strict_types=1);

namespace Bastion\Tests\Attack\Http;

use Bastion\Tests\Support\HttpHarness;
use PHPUnit\Framework\TestCase;

/** Abuser stories: hijack-installer, reinstall-over-live. */
final class InstallerAttackTest extends TestCase
{
    private const FORM = ['driver' => 'sqlite', 'username' => 'attacker', 'password' => 'correct horse battery staple'];

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
}
