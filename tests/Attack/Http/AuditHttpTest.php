<?php
declare(strict_types=1);

namespace Bastion\Tests\Attack\Http;

use Bastion\IdentityAccess\Domain\{NewPassword, Role, Username};
use Bastion\IdentityAccess\Infrastructure\AccountRepository;
use Bastion\Infrastructure\Database\Connection;
use Bastion\Tests\Support\{HttpHarness, MediaFixtures};
use ParagonIE\Halite\KeyFactory;
use PHPUnit\Framework\TestCase;

/** Abuser stories: audit-repudiation, audit-ui-wipe, audit-tamper (через UI и CLI). */
final class AuditHttpTest extends TestCase
{
    public function testSecurityRelevantActionsAreRecordedAndVerified(): void
    {
        $h = new HttpHarness();
        $h->installAndLogin();
        $h->get('/admin/entries/new');
        $res = $h->post('/admin/entries', ['title' => 'T', 'slug' => 't', 'blocks' => [['type' => 'paragraph', 'text' => 'x']]]);
        preg_match('~/admin/entries/([0-9a-f-]+)/edit~', $res->getHeaderLine('Location'), $m);
        $h->get("/admin/entries/{$m[1]}/edit");
        $h->post("/admin/entries/{$m[1]}/publish", []);
        $h->get('/admin/media');
        $h->upload('/admin/media', MediaFixtures::image(), 'a.jpg');

        $h->get('/admin/audit');
        $page = $h->body();
        self::assertStringContainsString('Integrity verified', $page);
        foreach (['installed', 'login_succeeded', 'second_factor_enrolled', 'entry_created', 'entry_published', 'media_uploaded'] as $action) {
            self::assertStringContainsString($action, $page, $action);
        }
        self::assertStringContainsString($m[1], $page, 'subject = id записи');

        $cli = 'BASTION_ROOT=' . escapeshellarg($h->paths->root) . ' ' . PHP_BINARY . ' ' . escapeshellarg(dirname(__DIR__, 3) . '/bin/bastion') . ' audit:verify 2>&1';
        exec($cli, $out, $code);
        self::assertSame(0, $code, implode("\n", $out));
        self::assertStringStartsWith('OK:', $out[0]);

        Connection::sqlite($h->paths->sqlite())->query('DELETE FROM ?_audit WHERE seq = (SELECT MAX(seq) FROM ?_audit)');
        exec($cli, $out2, $code2);
        self::assertSame(2, $code2, 'CLI сообщает о подмене ненулевым кодом (для cron/мониторинга)');
    }

    public function testTamperingShowsInTheAdminPanel(): void
    {
        $h = new HttpHarness();
        $h->installAndLogin();
        Connection::sqlite($h->paths->sqlite())->query("UPDATE ?_audit SET ip = '203.0.113.66' WHERE seq = 1");
        $h->get('/admin/audit');
        self::assertStringContainsString('Integrity check failed', $h->body());
    }

    public function testNoRouteCanWipeTheTrail(): void
    {
        $h = new HttpHarness();
        $h->installAndLogin();
        $h->get('/admin/audit');
        foreach (['/admin/audit', '/admin/audit/1', '/admin/audit/clear', '/admin/audit/1/delete'] as $path) {
            $h->get('/admin/audit');
            self::assertContains($h->post($path, [])->getStatusCode(), [403, 404, 405], $path);
        }
        $h->get('/admin/audit');
        self::assertStringContainsString('Integrity verified', $h->body());
    }

    public function testOnlyAdminsCanReadTheTrail(): void
    {
        $h = new HttpHarness();
        $h->installAndLogin();
        $u = Username::fromNative('writer');
        (new AccountRepository(Connection::sqlite($h->paths->sqlite()), KeyFactory::loadEncryptionKey($h->paths->encryptionKey())))
            ->create($u, NewPassword::forUser('another long passphrase here', $u), Role::Author);
        $author = $h->fresh();
        $author->get('/admin/login');
        $author->post('/admin/login', ['username' => 'writer', 'password' => 'another long passphrase here']);
        self::assertSame(403, $author->get('/admin/audit')->getStatusCode());
        self::assertSame('/admin/login', $h->fresh()->get('/admin/audit')->getHeaderLine('Location'));
    }
}
