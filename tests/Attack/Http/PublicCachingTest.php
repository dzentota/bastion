<?php
declare(strict_types=1);

namespace Bastion\Tests\Attack\Http;

use Bastion\Tests\Support\HttpHarness;
use PHPUnit\Framework\TestCase;

/** Публичные страницы за CDN. Abuser story: cdn-session-sharing. */
final class PublicCachingTest extends TestCase
{
    public function testPublicPagesCarryNoCookieAndAreCacheable(): void
    {
        $h = new HttpHarness();
        $h->installAndLogin();
        $h->get('/admin/entries/new?type=page');
        $res = $h->post('/admin/entries', ['type' => 'page', 'title' => 'P', 'slug' => 'p', 'blocks' => [['type' => 'paragraph', 'text' => 'x']]]);
        $h->get($res->getHeaderLine('Location'));
        $h->post(str_replace('/edit', '/publish', $res->getHeaderLine('Location')), []);

        $anon = $h->fresh();
        foreach (['/en', '/en/p', '/en/search?q=x', '/en/threats', '/en/nothing'] as $url) {
            $r = $anon->get($url);
            self::assertSame([], $r->getHeader('Set-Cookie'), $url);
            self::assertSame('public, max-age=60, s-maxage=300', $r->getHeaderLine('Cache-Control'), $url);
        }
        // даже вошедший сотрудник не получает cookie на публичной странице, а его cookie не попадает в кэш
        self::assertSame([], $h->get('/en/p')->getHeader('Set-Cookie'));

        $admin = $anon->get('/admin/login');
        self::assertNotSame([], $admin->getHeader('Set-Cookie'));
        self::assertSame('no-store', $admin->getHeaderLine('Cache-Control'));
    }

    public function testPublicAreaAcceptsOnlyReadsAndComments(): void
    {
        $h = new HttpHarness();
        $h->installAndLogin();
        $anon = $h->fresh();
        foreach (['/en', '/en/p', '/en/search'] as $url) {
            self::assertSame(405, $anon->post($url, [], false)->getStatusCode(), $url);
        }
        self::assertNotSame(405, $anon->post('/comments', [], false)->getStatusCode(), 'комментарии принимаются (и проверяются honeypot)');
    }
}
