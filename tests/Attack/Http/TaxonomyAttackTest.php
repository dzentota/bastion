<?php
declare(strict_types=1);

namespace Bastion\Tests\Attack\Http;

use Bastion\Tests\Support\HttpHarness;
use PHPUnit\Framework\TestCase;

/** term-enumeration-dos: листинги ограничены, перебор не стоит серверу работы. */
final class TaxonomyAttackTest extends TestCase
{
    private function post(HttpHarness $h, string $slug, string $categories, string $tags): int
    {
        $h->get('/admin/entries/new');
        $res = $h->post('/admin/entries', ['title' => ucfirst($slug), 'slug' => $slug, 'categories' => $categories, 'tags' => $tags,
            'blocks' => [['type' => 'paragraph', 'text' => 'Body']]]);
        if ($res->getStatusCode() === 303) {
            $edit = $res->getHeaderLine('Location');
            $h->get($edit);
            $h->post(str_replace('/edit', '/publish', $edit), []);
        }
        return $res->getStatusCode();
    }

    public function testListingsPaginateAndRejectAbuse(): void
    {
        $h = new HttpHarness();
        $h->installAndLogin();
        for ($i = 1; $i <= 21; $i++) {
            self::assertSame(303, $this->post($h, "post-{$i}", 'news', 'php'));
        }
        $this->post($h, 'draft-only', 'news', '') ;

        $anon = $h->fresh();
        self::assertSame(200, $anon->get('/en/category/news')->getStatusCode());
        self::assertSame(20, substr_count($anon->body(), '<article class="summary">'), 'фиксированный размер страницы');
        self::assertStringContainsString('/en/category/news?page=2', $anon->body());
        self::assertSame(200, $anon->get('/en/category/news?page=2')->getStatusCode());
        self::assertSame(2, substr_count($anon->body(), '<article class="summary">'));

        self::assertSame(200, $anon->get('/en/category/news?limit=100000&utm_source=x')->getStatusCode(), 'посторонние параметры игнорируются');
        self::assertSame(20, substr_count($anon->body(), '<article class="summary">'));
        self::assertSame(200, $anon->get('/en/post-1')->getStatusCode());
        self::assertStringContainsString('href="/en/tag/php"', $anon->body(), 'термины показаны на странице записи');

        foreach (['/en/category/news?page=3', '/en/category/news?page=51', '/en/category/news?page=999999999', '/en/category/news?page=0',
                  '/en/category/news?page[]=1', '/en/category/unknown', '/en/tag/news', '/en/tag/PHP', '/xx/category/news'] as $url) {
            self::assertSame(404, $anon->get($url)->getStatusCode(), $url);
        }
    }

    public function testPerEntryLimitsAndInvalidTermsAreRejected(): void
    {
        $h = new HttpHarness();
        $h->installAndLogin();
        $tooMany = implode(',', array_map(static fn ($i) => "t{$i}", range(1, 16)));
        self::assertSame(422, $this->post($h, 'a', '', $tooMany));
        self::assertSame(422, $this->post($h, 'b', 'a,b,c,d,e,f', ''));
        self::assertSame(422, $this->post($h, 'c', "x' OR 1=1--", ''));
        self::assertSame(422, $this->post($h, 'd', '', '<script>'));
        self::assertSame(303, $this->post($h, 'e', 'news, news', 'php'), 'дубли схлопываются');
    }
}
