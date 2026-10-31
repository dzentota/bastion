<?php
declare(strict_types=1);

namespace Bastion\Tests\Attack\Http;

use Bastion\IdentityAccess\Domain\{NewPassword, Role, Username};
use Bastion\IdentityAccess\Infrastructure\AccountRepository;
use Bastion\Infrastructure\Database\Connection;
use Bastion\Tests\Support\HttpHarness;
use ParagonIE\Halite\KeyFactory;
use PHPUnit\Framework\TestCase;

/** Degraded Mode всегда виден администратору и не раскрывает конфигурацию остальным. */
final class DegradedModeHttpTest extends TestCase
{
    public function testAdminSeesDegradedModeAuthorDoesNot(): void
    {
        $h = new HttpHarness();
        $h->installAndLogin();
        $h->get('/admin');
        self::assertStringContainsString('Degraded Mode: update channel is not configured', $h->body());
        self::assertStringContainsString('Degraded Mode: media stored on the web server', $h->body());

        $u = Username::fromNative('writer');
        (new AccountRepository(Connection::sqlite($h->paths->sqlite()), KeyFactory::loadEncryptionKey($h->paths->encryptionKey())))
            ->create($u, NewPassword::forUser('another long passphrase here', $u), Role::Author);
        $author = $h->fresh();
        $author->get('/admin/login');
        $author->post('/admin/login', ['username' => 'writer', 'password' => 'another long passphrase here']);
        $author->get('/admin');
        self::assertStringContainsString('Content', $author->body());
        self::assertStringNotContainsString('Degraded Mode', $author->body());
    }
}
