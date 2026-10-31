<?php
declare(strict_types=1);

namespace Bastion\Tests\Attack\Http;

use Bastion\Infrastructure\Database\Connection;
use Bastion\Tests\Support\HttpHarness;
use PHPUnit\Framework\TestCase;

/** Язык админки на пользователя. Abuser story: ui-locale-tampering. */
final class AdminLocaleHttpTest extends TestCase
{
    public function testAdminSwitchesInterfaceLanguage(): void
    {
        $h = new HttpHarness();
        $h->installAndLogin();
        $h->get('/admin');
        self::assertStringContainsString('<html lang="en">', $h->body());
        self::assertStringContainsString('New post', $h->body());

        self::assertSame('/admin', $h->post('/admin/locale', ['lang' => 'ru'])->getHeaderLine('Location'));
        $h->get('/admin');
        self::assertStringContainsString('<html lang="ru">', $h->body());
        self::assertStringContainsString('Новая запись', $h->body());

        $h->post('/admin/locale', ['lang' => 'en']);
        $h->get('/admin');
        self::assertStringContainsString('New post', $h->body());
    }

    public function testSiteDefaultLanguageIsUsedUntilTheUserChooses(): void
    {
        $h = new HttpHarness();
        $h->installAndLogin(languages: 'ru, en');
        $h->get('/admin');
        self::assertStringContainsString('Новая запись', $h->body());
    }

    public function testOnlyCataloguedLanguagesAndOnlyOwnAccount(): void
    {
        $h = new HttpHarness();
        $h->installAndLogin();
        $db = Connection::sqlite($h->paths->sqlite());
        foreach (['de', 'xx', '../en', '"><b>', ''] as $lang) {
            $h->get('/admin');
            self::assertSame('/admin', $h->post('/admin/locale', ['lang' => $lang])->getHeaderLine('Location'), $lang);
        }
        self::assertNull($db->selectCell('SELECT locale FROM ?_accounts'));

        $h->get('/admin');
        self::assertSame(403, $h->post('/admin/locale', ['lang' => 'ru'], false)->getStatusCode(), 'CSRF');
        self::assertSame(403, $h->fresh()->post('/admin/locale', ['lang' => 'ru'], false)->getStatusCode(), 'аноним без сессии');
        self::assertNull($db->selectCell('SELECT locale FROM ?_accounts'));
    }

    public function testRedirectTargetCannotBeInfluenced(): void
    {
        $h = new HttpHarness();
        $h->installAndLogin();
        $h->get('/admin');
        $res = $h->post('/admin/locale', ['lang' => 'ru', 'return' => 'https://evil.example/', 'next' => '//evil.example']);
        self::assertSame('/admin', $res->getHeaderLine('Location'));
    }
}
