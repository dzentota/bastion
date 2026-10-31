<?php
declare(strict_types=1);

namespace Bastion\Tests\Attack\Http;

use Bastion\Tests\Support\HttpHarness;
use PHPUnit\Framework\TestCase;

/** Страницы: вне ленты, без терминов и комментариев; системные слаги заняты. */
final class PagesHttpTest extends TestCase
{
    /** @param array<string, mixed> $extra */
    private function create(HttpHarness $h, string $slug, array $extra, bool $publish = true): int
    {
        $h->get('/admin/entries/new');
        $res = $h->post('/admin/entries', $extra + ['title' => ucfirst($slug), 'slug' => $slug, 'blocks' => [['type' => 'paragraph', 'text' => 'Body']]]);
        if ($publish && $res->getStatusCode() === 303) {
            $edit = $res->getHeaderLine('Location');
            $h->get($edit);
            $h->post(str_replace('/edit', '/publish', $edit), []);
        }
        return $res->getStatusCode();
    }

    public function testPageLivesOutsideTheFeed(): void
    {
        $h = new HttpHarness();
        $h->installAndLogin();
        self::assertSame(303, $this->create($h, 'about', ['type' => 'page', 'categories' => 'news', 'tags' => 'php']));
        self::assertSame(303, $this->create($h, 'hello', ['type' => 'post', 'categories' => 'news']));

        $anon = $h->fresh();
        self::assertSame(200, $anon->get('/about')->getStatusCode());
        self::assertStringNotContainsString('comment-form', $anon->body(), 'у страницы нет формы комментария');
        self::assertStringNotContainsString('/category/news', $anon->body(), 'термины страницы не сохраняются');

        $anon->get('/');
        self::assertStringContainsString('/hello', $anon->body());
        self::assertStringNotContainsString('/about', $anon->body(), 'страницы нет в ленте');
        $anon->get('/category/news');
        self::assertStringNotContainsString('/about', $anon->body());

        $h->get('/admin');
        self::assertStringContainsString('page', $h->body());
    }

    public function testCommentsOnPagesAreRefused(): void
    {
        $h = new HttpHarness();
        $h->installAndLogin();
        $this->create($h, 'about', ['type' => 'page']);
        $h->get('/admin');
        preg_match('~/admin/entries/([0-9a-f-]+)/edit~', $h->body(), $m);
        $res = $h->fresh()->post('/comments', ['entry' => $m[1], 'author' => 'Eve', 'body' => 'hi', '_timestamp' => 'x'], withToken: false);
        self::assertNotSame(303, $res->getStatusCode());
        self::assertNotSame(200, $res->getStatusCode());
    }

    public function testReservedSlugsAndUnknownTypeAreRejected(): void
    {
        $h = new HttpHarness();
        $h->installAndLogin();
        foreach (['admin', 'category', 'tag', 'media'] as $slug) {
            self::assertSame(422, $this->create($h, $slug, ['type' => 'page'], false), $slug);
        }
        self::assertSame(422, $this->create($h, 'odd', ['type' => 'gallery'], false));
        self::assertSame(303, $this->create($h, 'no-type', [], false), 'без поля type создаётся пост');
    }

    public function testSiteMenuListsPublishedPagesInOrder(): void
    {
        $h = new HttpHarness();
        $h->installAndLogin();
        self::assertSame(303, $this->create($h, 'contact', ['type' => 'page', 'in_menu' => '1', 'menu_position' => '20']));
        self::assertSame(303, $this->create($h, 'about', ['type' => 'page', 'in_menu' => '1', 'menu_position' => '5', 'title' => 'About <us>']));
        self::assertSame(303, $this->create($h, 'hidden', ['type' => 'page']));
        self::assertSame(303, $this->create($h, 'draft-page', ['type' => 'page', 'in_menu' => '1'], publish: false));
        self::assertSame(303, $this->create($h, 'a-post', ['in_menu' => '1']), 'у постов флажок игнорируется');

        $anon = $h->fresh();
        $anon->get('/');
        preg_match('~<nav class="menu"[^>]*>(.*?)</nav>~s', $anon->body(), $m);
        self::assertSame(['/about', '/contact'], preg_match_all('~href="([^"]+)"~', $m[1] ?? '', $hrefs) ? $hrefs[1] : [], 'только опубликованные страницы, по позиции');
        self::assertStringContainsString('About &lt;us&gt;', $m[1]);
        $anon->get('/category/none');
        self::assertStringContainsString('class="menu"', $anon->body(), 'меню и на служебных страницах темы');

        self::assertSame(422, $this->create($h, 'bad-pos', ['type' => 'page', 'in_menu' => '1', 'menu_position' => '0'], publish: false));
        self::assertSame(422, $this->create($h, 'bad-pos2', ['type' => 'page', 'in_menu' => '1', 'menu_position' => '1; DROP'], publish: false));

        // снять флажок — пункт уходит из меню
        $h->get('/admin');
        preg_match('~/admin/entries/([0-9a-f-]+)/edit">Contact~', $h->body(), $id);
        $h->get("/admin/entries/{$id[1]}/edit");
        $h->post("/admin/entries/{$id[1]}", ['title' => 'Contact', 'slug' => 'contact', 'blocks' => [['type' => 'paragraph', 'text' => 'Body']]]);
        self::assertStringNotContainsString('href="/contact"', (string) $h->fresh()->get('/')->getBody());
    }
}
