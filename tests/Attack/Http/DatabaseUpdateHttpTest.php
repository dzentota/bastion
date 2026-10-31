<?php
declare(strict_types=1);

namespace Bastion\Tests\Attack\Http;

use Bastion\IdentityAccess\Domain\{NewPassword, Role, Username};
use Bastion\IdentityAccess\Infrastructure\AccountRepository;
use Bastion\Infrastructure\Database\Connection;
use Bastion\Tests\Support\HttpHarness;
use OTPHP\TOTP;
use ParagonIE\Halite\KeyFactory;
use PHPUnit\Framework\TestCase;

/** Abuser stories: unauthorized-migration, half-migrated-site (ADR-0018). */
final class DatabaseUpdateHttpTest extends TestCase
{
    public function testPendingMigrationPutsSiteIntoMaintenanceUntilAdminApplies(): void
    {
        [$h, $secret] = $this->siteWithPendingUpdate();

        self::assertSame(503, $h->fresh()->get('/en')->getStatusCode(), 'публичный сайт на старой схеме не работает');
        self::assertSame(503, $h->get('/admin/media')->getStatusCode());
        self::assertSame('/admin/database', $h->get('/admin')->getHeaderLine('Location'));

        $h->get('/admin/database');
        self::assertStringContainsString('0003_account_locale', $h->body());
        self::assertSame(303, $h->post('/admin/database', ['code' => $this->nextCode($secret)])->getStatusCode());

        self::assertSame(200, $h->fresh()->get('/en')->getStatusCode());
        self::assertNotEmpty(glob($h->paths->backups() . '/db-*.sqlite'), 'копия снята до миграции');
        $h->get('/admin/audit');
        self::assertStringContainsString('schema_migrated', $h->body());
    }

    public function testFreshTotpIsRequiredAndCannotBeReplayed(): void
    {
        [$h, $secret] = $this->siteWithPendingUpdate();
        $h->get('/admin/database');
        self::assertSame(401, $h->post('/admin/database', ['code' => '000000'])->getStatusCode());
        self::assertSame(401, $h->post('/admin/database', [])->getStatusCode());

        // код, которым админ только что вошёл, повторно не принимается
        $used = TOTP::createFromSecret($secret)->now();
        self::assertSame(401, $h->post('/admin/database', ['code' => $used])->getStatusCode());
        self::assertSame(503, $h->fresh()->get('/en')->getStatusCode(), 'ничего не применено');
    }

    public function testCsrfIsRequired(): void
    {
        [$h, $secret] = $this->siteWithPendingUpdate();
        $h->get('/admin/database');
        self::assertSame(403, $h->post('/admin/database', ['code' => $this->nextCode($secret)], false)->getStatusCode());
        self::assertSame(503, $h->fresh()->get('/en')->getStatusCode());
    }

    public function testNonAdminsAndAnonymousCannotMigrate(): void
    {
        [$h] = $this->siteWithPendingUpdate();
        $u = Username::fromNative('writer');
        (new AccountRepository(Connection::sqlite($h->paths->sqlite()), KeyFactory::loadEncryptionKey($h->paths->encryptionKey())))
            ->create($u, NewPassword::forUser('another long passphrase here', $u), Role::Author);
        $author = $h->fresh();
        $author->get('/admin/login');
        $author->post('/admin/login', ['username' => 'writer', 'password' => 'another long passphrase here']);
        self::assertSame(403, $author->get('/admin/database')->getStatusCode());
        $author->get('/admin/login');
        self::assertSame(403, $author->post('/admin/database', ['code' => '123456'])->getStatusCode());

        self::assertSame('/admin/login', $h->fresh()->get('/admin/database')->getHeaderLine('Location'));
        self::assertSame(503, $h->fresh()->get('/en')->getStatusCode());
    }

    /** @return array{0: HttpHarness, 1: string} установка, затем «новый релиз» с неприменённой миграцией */
    private function siteWithPendingUpdate(): array
    {
        $h = new HttpHarness();
        $secret = $h->installAndLogin();
        // сайт на прошлом релизе: последней миграции нет ни в учёте, ни в схеме
        $db = Connection::sqlite($h->paths->sqlite());
        $db->query("DELETE FROM ?_schema_migrations WHERE id = '0003_account_locale'");
        $db->query('ALTER TABLE ?_accounts DROP COLUMN locale');
        return [$h, $secret];
    }

    /** Код следующего шага TOTP (окно ±1): текущий уже израсходован на вход. */
    private function nextCode(string $secret): string
    {
        $totp = TOTP::createFromSecret($secret);
        return $totp->at(time() + $totp->getPeriod());
    }
}
