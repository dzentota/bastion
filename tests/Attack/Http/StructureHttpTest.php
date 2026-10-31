<?php
declare(strict_types=1);

namespace Bastion\Tests\Attack\Http;

use Bastion\IdentityAccess\Domain\{NewPassword, Role, Username};
use Bastion\IdentityAccess\Infrastructure\AccountRepository;
use Bastion\Infrastructure\Database\Connection;
use Bastion\Tests\Support\HttpHarness;
use ParagonIE\Halite\KeyFactory;
use PHPUnit\Framework\TestCase;
use SecureDb\Db;

/** Дерево страниц, меню и новые блоки через HTTP. Abuser stories: page-tree-cycle, menu-tamper. */
final class StructureHttpTest extends TestCase
{
    private HttpHarness $h;
    private Db $db;

    protected function setUp(): void
    {
        $this->h = new HttpHarness();
        $this->h->installAndLogin(languages: 'en, ru');
        $this->db = Connection::sqlite($this->h->paths->sqlite());
    }

    public function testTreeDrivesBreadcrumbsSectionAndChildren(): void
    {
        $docs = $this->page('docs', 'Docs');
        $install = $this->page('setup', 'Install', ['parent' => $docs, 'page_position' => '2']);
        $intro = $this->page('intro', 'Intro', ['parent' => $docs, 'page_position' => '1']);
        $mysql = $this->page('mysql', 'MySQL', ['parent' => $install]);
        $this->page('secret', 'Secret draft', ['parent' => $docs], publish: false);

        $anon = $this->h->fresh();
        $page = (string) $anon->get('/en/mysql')->getBody();
        self::assertStringContainsString('<a href="/en/docs">Docs</a> › <a href="/en/setup">Install</a> ›', $page, 'крошки');
        self::assertMatchesRegularExpression('~/en/intro.*/en/setup.*/en/mysql~s', $page, 'раздел по порядку');
        self::assertStringContainsString('<a href="/en/mysql" aria-current="page">', $page);
        self::assertStringNotContainsString('Secret draft', $page, 'черновики не видны в навигации');
        $docsPage = (string) $anon->get('/en/docs')->getBody();
        self::assertStringContainsString('In this section', $docsPage);
        self::assertStringNotContainsString('Secret draft', $docsPage);
        self::assertSame(200, $anon->get('/en/setup')->getStatusCode(), 'адрес не зависит от дерева');
        unset($intro, $mysql);
    }

    public function testCyclesDepthAndCrossLanguageParentsAreRefused(): void
    {
        $a = $this->page('a', 'A');
        $b = $this->page('b', 'B', ['parent' => $a]);
        $c = $this->page('c', 'C', ['parent' => $b]);
        $d = $this->page('d', 'D', ['parent' => $c]);
        self::assertSame(422, $this->save($a, ['parent' => $d]), 'цикл');
        self::assertSame(422, $this->save($a, ['parent' => $a]), 'сам себе родитель');
        self::assertSame(422, $this->createStatus('e', ['parent' => $d]), 'пятый уровень');
        $ru = $this->page('ru-page', 'RU', ['lang' => 'ru']);
        self::assertSame(422, $this->save($b, ['parent' => $ru]), 'другой язык');
        $post = $this->post('a-post');
        self::assertSame(422, $this->save($b, ['parent' => $post]), 'родитель — пост');
        self::assertSame(422, $this->save($b, ['parent' => 'not-a-uuid']));
        self::assertSame(422, $this->save($b, ['page_position' => '1000']));
        self::assertNull($this->db->selectCell('SELECT parent_id FROM ?_entries WHERE id = ?', $a));
        // цикл, внесённый прямо в БД, не вешает рендер
        $this->db->query('UPDATE ?_entries SET parent_id = ? WHERE id = ?', $d, $a);
        self::assertSame(200, $this->h->fresh()->get('/en/c')->getStatusCode());
    }

    public function testMenuEditorIsForPublishersAndOnlyTakesPagesOfTheLanguage(): void
    {
        $about = $this->page('about', 'About');
        $docs = $this->page('docs', 'Docs');
        $ru = $this->page('o-nas', 'О нас', ['lang' => 'ru']);
        $post = $this->post('news');

        $this->h->get('/admin/menu');
        $this->h->post('/admin/menu', ['lang' => 'en', 'add' => $about, 'add_position' => '20']);
        $this->h->get('/admin/menu');
        $this->h->post('/admin/menu', ['lang' => 'en', 'add' => $docs, 'add_position' => '10']);
        foreach ([$ru, $post, 'x'] as $bad) {
            $this->h->get('/admin/menu');
            $this->h->post('/admin/menu', ['lang' => 'en', 'add' => $bad, 'add_position' => '5']);
        }
        self::assertSame(['/en/docs', '/en/about'], $this->menuLinks('/en'));

        $this->h->get('/admin/menu');
        $this->h->post('/admin/menu', ['lang' => 'en', 'position' => [$about => '1', $docs => '30', $ru => '1'], 'remove' => []]);
        self::assertSame(['/en/about', '/en/docs'], $this->menuLinks('/en'));
        $this->h->get('/admin/menu');
        $this->h->post('/admin/menu', ['lang' => 'en', 'position' => [$about => '1', $docs => '30'], 'remove' => [$docs]]);
        self::assertSame(['/en/about'], $this->menuLinks('/en'));
        self::assertSame([], $this->menuLinks('/ru'), 'у другого языка своё меню');

        $u = Username::fromNative('writer');
        (new AccountRepository($this->db, KeyFactory::loadEncryptionKey($this->h->paths->encryptionKey())))
            ->create($u, NewPassword::forUser('another long passphrase here', $u), Role::Author);
        $author = $this->h->fresh();
        $author->get('/admin/login');
        $author->post('/admin/login', ['username' => 'writer', 'password' => 'another long passphrase here']);
        self::assertSame(403, $author->get('/admin/menu')->getStatusCode());
        $author->get('/admin');
        self::assertSame(403, $author->post('/admin/menu', ['lang' => 'en', 'remove' => [$about], 'position' => [$about => '1']])->getStatusCode());
        self::assertSame(['/en/about'], $this->menuLinks('/en'));
    }

    public function testRichBlocksRoundTripThroughTheEditor(): void
    {
        $this->h->get('/admin/entries/new?type=page');
        $res = $this->h->post('/admin/entries', ['type' => 'page', 'title' => 'Blocks', 'slug' => 'blocks', 'blocks' => [
            ['type' => 'code', 'option' => 'bash', 'text' => 'composer install'],
            ['type' => 'table', 'option' => 'header', 'text' => "A | B\n1 | 2"],
            ['type' => 'callout', 'option' => 'danger', 'text' => 'Careful'],
            ['type' => 'code', 'option' => 'evil', 'text' => 'x'],
        ]]);
        self::assertSame(303, $res->getStatusCode());
        $edit = $res->getHeaderLine('Location');
        $this->h->get($edit);
        self::assertStringContainsString('<option value="bash" selected>', $this->h->body());
        self::assertStringContainsString('<option value="header" selected>', $this->h->body());
        $this->h->post(str_replace('/edit', '/publish', $edit), []);
        $page = (string) $this->h->fresh()->get('/en/blocks')->getBody();
        self::assertStringContainsString('<code class="language-bash">composer install</code>', $page);
        self::assertStringContainsString('<code class="language-text">x</code>', $page, 'неизвестный язык → text');
        self::assertStringContainsString('<th>A</th>', $page);
        self::assertStringContainsString('callout-danger', $page);

        $this->h->get('/admin/entries/new?type=page');
        self::assertSame(422, $this->h->post('/admin/entries', ['type' => 'page', 'title' => 'Big', 'slug' => 'big', 'blocks' => [
            ['type' => 'table', 'text' => implode("\n", array_fill(0, 51, 'a'))],
        ]])->getStatusCode());
    }

    /** @param array<string, string> $extra */
    private function page(string $slug, string $title, array $extra = [], bool $publish = true): string
    {
        $this->h->get('/admin/entries/new?type=page');
        $res = $this->h->post('/admin/entries', $extra + ['type' => 'page', 'title' => $title, 'slug' => $slug, 'blocks' => [['type' => 'paragraph', 'text' => 'Body']]]);
        self::assertSame(303, $res->getStatusCode(), $slug . ': ' . $this->h->body());
        preg_match('~/admin/entries/([0-9a-f-]+)/edit~', $res->getHeaderLine('Location'), $m);
        if ($publish) {
            $this->h->get("/admin/entries/{$m[1]}/edit");
            $this->h->post("/admin/entries/{$m[1]}/publish", []);
        }
        return $m[1];
    }

    private function post(string $slug): string
    {
        $this->h->get('/admin/entries/new');
        $res = $this->h->post('/admin/entries', ['title' => 'P', 'slug' => $slug, 'blocks' => [['type' => 'paragraph', 'text' => 'x']]]);
        preg_match('~/admin/entries/([0-9a-f-]+)/edit~', $res->getHeaderLine('Location'), $m);
        return $m[1];
    }

    /** @param array<string, string> $extra */
    private function createStatus(string $slug, array $extra): int
    {
        $this->h->get('/admin/entries/new?type=page');
        return $this->h->post('/admin/entries', $extra + ['type' => 'page', 'title' => 'X', 'slug' => $slug, 'blocks' => [['type' => 'paragraph', 'text' => 'x']]])->getStatusCode();
    }

    /** @param array<string, string> $extra */
    private function save(string $id, array $extra): int
    {
        $this->h->get("/admin/entries/{$id}/edit");
        preg_match('~name="slug" value="([^"]+)"~', $this->h->body(), $s);
        preg_match('~name="title" value="([^"]+)"~', $this->h->body(), $t);
        return $this->h->post("/admin/entries/{$id}", $extra + ['title' => $t[1], 'slug' => $s[1], 'blocks' => [['type' => 'paragraph', 'text' => 'Body']]])->getStatusCode();
    }

    /** @return list<string> */
    private function menuLinks(string $home): array
    {
        $page = (string) $this->h->fresh()->get($home)->getBody();
        preg_match('~<nav class="menu"[^>]*>(.*?)</nav>~s', $page, $m);
        return preg_match_all('~href="([^"]+)"~', $m[1] ?? '', $hrefs) ? $hrefs[1] : [];
    }
}
