<?php
declare(strict_types=1);

namespace Bastion\Tests\Attack\Http;

use Bastion\IdentityAccess\Domain\{NewPassword, Role, Username};
use Bastion\IdentityAccess\Infrastructure\AccountRepository;
use Bastion\Infrastructure\Database\Connection;
use Bastion\Tests\Support\HttpHarness;
use ParagonIE\Halite\KeyFactory;
use PHPUnit\Framework\TestCase;

/** Переводы записей. Abuser stories: translation-hijack, language-parameter-abuse, draft-translation-leak, legacy-redirect-abuse. */
final class I18nHttpTest extends TestCase
{
    private HttpHarness $h;

    protected function setUp(): void
    {
        $this->h = new HttpHarness();
        $this->h->installAndLogin(languages: 'en, ru');
    }

    public function testTranslationLifecycle(): void
    {
        $en = $this->create('hello', 'Hello', 'en');
        $this->publish($en);

        // перевод: черновик с тем же slug в другом языке
        $ru = $this->translate($en, 'ru');
        self::assertNotSame($en, $ru);
        $this->h->get("/admin/entries/{$ru}/edit");
        self::assertSame(303, $this->h->post("/admin/entries/{$ru}", ['title' => 'Привет', 'slug' => 'hello', 'blocks' => [['type' => 'paragraph', 'text' => 'Текст']]])->getStatusCode());

        $anon = $this->h->fresh();
        self::assertSame(404, $anon->get('/ru/hello')->getStatusCode(), 'черновик перевода не опубликован');
        $page = (string) $anon->get('/en/hello')->getBody();
        self::assertStringNotContainsString('/ru/hello', $page, 'переключатель и hreflang не ведут на черновик');
        self::assertStringContainsString('<html lang="en">', $page);
        self::assertStringContainsString('href="/ru"', $page, 'без перевода — главная языка');

        $this->publish($ru);
        $page = (string) $anon->get('/en/hello')->getBody();
        self::assertStringContainsString('<link rel="alternate" hreflang="ru" href="/ru/hello">', $page);
        self::assertStringContainsString('<link rel="alternate" hreflang="en" href="/en/hello">', $page);
        $ruPage = (string) $anon->get('/ru/hello')->getBody();
        self::assertStringContainsString('<html lang="ru">', $ruPage);
        self::assertStringContainsString('Привет', $ruPage);

        // главная каждого языка — только свои записи
        self::assertStringNotContainsString('Привет', (string) $anon->get('/en')->getBody());
        self::assertStringContainsString('Привет', (string) $anon->get('/ru')->getBody());

        // одна запись на язык в группе
        $this->h->get("/admin/entries/{$en}/edit");
        $this->h->post("/admin/entries/{$en}/translations", ['lang' => 'ru']);
        self::assertSame(2, (int) Connection::sqlite($this->h->paths->sqlite())->selectCell('SELECT COUNT(*) FROM ?_entries'));
    }

    public function testOldAddressesMoveAndOnlyConfiguredLanguagesResolve(): void
    {
        $this->publish($this->create('hello', 'Hello', 'en'));
        $this->publish($this->create('only-ru', 'Только', 'ru'));
        $anon = $this->h->fresh();

        self::assertSame('/en', $anon->get('/')->getHeaderLine('Location'));
        $moved = $anon->get('/hello');
        self::assertSame(301, $moved->getStatusCode());
        self::assertSame('/en/hello', $moved->getHeaderLine('Location'));
        self::assertSame('/ru/only-ru', $anon->get('/only-ru')->getHeaderLine('Location'), 'старый адрес записи не на языке по умолчанию');
        self::assertSame('/en/category/news', $anon->get('/category/news')->getHeaderLine('Location'));
        self::assertSame(404, $anon->get('/nothing-here')->getStatusCode());

        foreach (['/de/hello', '/xx', '/ru/hello', '/en/only-ru', '/EN/hello', '/e"n/hello'] as $url) {
            self::assertSame(404, $anon->get($url)->getStatusCode(), $url);
        }
    }

    public function testEditorRejectsUnknownLanguages(): void
    {
        $this->h->get('/admin/entries/new');
        foreach (['de', 'xx', '"><script>', ''] as $i => $lang) {
            $res = $this->h->post('/admin/entries', ['title' => 'T', 'slug' => "t{$i}", 'lang' => $lang, 'blocks' => [['type' => 'paragraph', 'text' => 'x']]]);
            self::assertSame(422, $res->getStatusCode(), $lang);
        }
        $this->h->get('/admin/entries/new');
        $id = $this->create('x', 'X', 'en');
        $this->h->get("/admin/entries/{$id}/edit");
        $this->h->post("/admin/entries/{$id}/translations", ['lang' => 'de']);
        $this->h->get("/admin/entries/{$id}/edit");
        $this->h->post("/admin/entries/{$id}/translations", ['lang' => 'en']);
        self::assertSame(1, (int) Connection::sqlite($this->h->paths->sqlite())->selectCell('SELECT COUNT(*) FROM ?_entries'), 'неизвестные языки, de и дубль en отклонены');
    }

    public function testLanguageOfAnEntryCannotBeChangedAfterCreation(): void
    {
        $id = $this->create('fixed', 'Fixed', 'en');
        $this->h->get("/admin/entries/{$id}/edit");
        $this->h->post("/admin/entries/{$id}", ['title' => 'Fixed', 'slug' => 'fixed', 'lang' => 'ru', 'blocks' => [['type' => 'paragraph', 'text' => 'x']]]);
        self::assertSame('en', Connection::sqlite($this->h->paths->sqlite())->selectCell('SELECT lang FROM ?_entries WHERE id = ?', $id));
    }

    public function testAuthorCannotTranslateSomeoneElsesEntry(): void
    {
        $id = $this->create('owners', 'Owner\'s', 'en');
        $u = Username::fromNative('writer');
        (new AccountRepository(Connection::sqlite($this->h->paths->sqlite()), KeyFactory::loadEncryptionKey($this->h->paths->encryptionKey())))
            ->create($u, NewPassword::forUser('another long passphrase here', $u), Role::Author);
        $author = $this->h->fresh();
        $author->get('/admin/login');
        $author->post('/admin/login', ['username' => 'writer', 'password' => 'another long passphrase here']);
        $author->get('/admin');
        self::assertSame(404, $author->post("/admin/entries/{$id}/translations", ['lang' => 'ru'])->getStatusCode());
        self::assertSame(1, (int) Connection::sqlite($this->h->paths->sqlite())->selectCell('SELECT COUNT(*) FROM ?_entries'));
    }

    private function create(string $slug, string $title, string $lang): string
    {
        $this->h->get('/admin/entries/new');
        $res = $this->h->post('/admin/entries', ['title' => $title, 'slug' => $slug, 'lang' => $lang, 'blocks' => [['type' => 'paragraph', 'text' => 'Body']]]);
        self::assertSame(303, $res->getStatusCode(), $this->h->body());
        preg_match('~/admin/entries/([0-9a-f-]+)/edit~', $res->getHeaderLine('Location'), $m);
        return $m[1];
    }

    private function translate(string $id, string $lang): string
    {
        $this->h->get("/admin/entries/{$id}/edit");
        self::assertStringContainsString('Add translation', $this->h->body());
        $res = $this->h->post("/admin/entries/{$id}/translations", ['lang' => $lang]);
        preg_match('~/admin/entries/([0-9a-f-]+)/edit~', $res->getHeaderLine('Location'), $m);
        return $m[1];
    }

    private function publish(string $id): void
    {
        $this->h->get("/admin/entries/{$id}/edit");
        self::assertSame(303, $this->h->post("/admin/entries/{$id}/publish", [])->getStatusCode());
    }
}
