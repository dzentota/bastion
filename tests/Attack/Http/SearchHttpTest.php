<?php
declare(strict_types=1);

namespace Bastion\Tests\Attack\Http;

use Bastion\Tests\Support\HttpHarness;
use PHPUnit\Framework\TestCase;

/** Поиск. Abuser stories: search-draft-leak, search-reflected-xss, search-query-injection, search-dos. */
final class SearchHttpTest extends TestCase
{
    private HttpHarness $h;

    protected function setUp(): void
    {
        $this->h = new HttpHarness();
        $this->h->installAndLogin(languages: 'en, ru');
    }

    public function testFindsPublishedEntriesOfTheLanguageOnly(): void
    {
        $id = $this->page('setup', 'Installation guide', 'Upload the files to your hosting account.', 'en');
        $this->page('ustanovka', 'Установка', 'Загрузите файлы на хостинг.', 'ru');
        $this->page('draft', 'Secret draft', 'unreleasedword appears only here', 'en', publish: false);

        $anon = $this->h->fresh();
        $page = (string) $anon->get('/en/search?q=hosting')->getBody();
        self::assertStringContainsString('href="/en/setup"', $page);
        self::assertStringContainsString('<mark>hosting</mark>', $page);
        self::assertStringNotContainsString('/ru/ustanovka', $page, 'другой язык');
        self::assertStringContainsString('href="/ru/ustanovka"', (string) $anon->get('/ru/search?q=' . rawurlencode('хост'))->getBody(), 'префикс, кириллица');
        self::assertStringContainsString('Nothing found', (string) $anon->get('/en/search?q=unreleasedword')->getBody(), 'черновик');

        // сохранённые, но не опубликованные изменения не ищутся до публикации
        $this->h->get("/admin/entries/{$id}/edit");
        $this->h->post("/admin/entries/{$id}", ['title' => 'Installation guide', 'slug' => 'setup', 'blocks' => [['type' => 'paragraph', 'text' => 'Now with embargoedterm inside.']]]);
        self::assertStringContainsString('Nothing found', (string) $anon->get('/en/search?q=embargoedterm')->getBody());
        $this->h->get("/admin/entries/{$id}/edit");
        $this->h->post("/admin/entries/{$id}/publish", []);
        self::assertStringContainsString('href="/en/setup"', (string) $anon->get('/en/search?q=embargoedterm')->getBody());
        self::assertStringContainsString('Nothing found', (string) $anon->get('/en/search?q=hosting')->getBody(), 'старый текст ушёл из индекса');
    }

    public function testHostileQueriesAreInertAndEscaped(): void
    {
        $this->page('a', 'Alpha', 'alpha text', 'en');
        $anon = $this->h->fresh();
        $res = $anon->get('/en/search?q=' . rawurlencode('"><script>alert(1)</script>'));
        self::assertSame(200, $res->getStatusCode());
        self::assertSame('noindex', $res->getHeaderLine('X-Robots-Tag'));
        $page = (string) $res->getBody();
        self::assertStringNotContainsString('<script>alert', $page);
        self::assertStringContainsString('value="&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;"', $page);
        foreach (['title:alpha', 'alpha NEAR(x y)', '"', '*', 'alpha) OR (1', str_repeat('a', 201), 'NOT alpha', '{title}: alpha'] as $q) {
            self::assertSame(200, $anon->get('/en/search?q=' . rawurlencode($q))->getStatusCode(), $q);
        }
        self::assertStringContainsString('too long', (string) $anon->get('/en/search?q=' . str_repeat('a', 201))->getBody());
        self::assertSame(200, $anon->get('/en/search?q[]=x')->getStatusCode());
        self::assertSame(404, $anon->get('/xx/search?q=alpha')->getStatusCode());
    }

    private function page(string $slug, string $title, string $text, string $lang, bool $publish = true): string
    {
        $this->h->get('/admin/entries/new?type=page');
        $res = $this->h->post('/admin/entries', ['type' => 'page', 'lang' => $lang, 'title' => $title, 'slug' => $slug, 'blocks' => [['type' => 'paragraph', 'text' => $text]]]);
        preg_match('~/admin/entries/([0-9a-f-]+)/edit~', $res->getHeaderLine('Location'), $m);
        if ($publish) {
            $this->h->get("/admin/entries/{$m[1]}/edit");
            $this->h->post("/admin/entries/{$m[1]}/publish", []);
        }
        return $m[1];
    }
}
