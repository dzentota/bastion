<?php
declare(strict_types=1);

namespace Bastion\Tests\Attack\Http;

use Bastion\Tests\Support\{HttpHarness, MediaFixtures};
use PHPUnit\Framework\TestCase;

/** Abuser stories: upload-rce, media-path-traversal, media-content-sniffing, exif-leak (через HTTP). */
final class MediaHttpAttackTest extends TestCase
{
    private static function uploadedId(HttpHarness $h): string
    {
        $h->get('/admin/media');
        preg_match('~/media/([0-9a-f]{32})~', $h->body(), $m);
        return $m[1] ?? '';
    }

    public function testImageRoundTripIsSanitisedAndServedSafely(): void
    {
        $h = new HttpHarness();
        $h->installAndLogin();
        $h->get('/admin/media');
        $res = $h->upload('/admin/media', MediaFixtures::jpegWithExif('secret'), '../../../public/shell.php.jpg', 'application/x-php');
        self::assertSame(303, $res->getStatusCode());
        $id = self::uploadedId($h);
        self::assertNotSame('', $id);

        // имя клиента не влияет на файловую систему
        self::assertFileDoesNotExist($h->paths->root . '/public/shell.php.jpg');
        self::assertSame([], glob($h->paths->var('media') . '/*/*.php') ?: []);

        $served = $h->fresh()->get('/media/' . $id);
        self::assertSame(200, $served->getStatusCode());
        self::assertSame('image/jpeg', $served->getHeaderLine('Content-Type'));
        self::assertSame('nosniff', $served->getHeaderLine('X-Content-Type-Options'));
        self::assertSame("default-src 'none'; sandbox", $served->getHeaderLine('Content-Security-Policy'));
        self::assertStringNotContainsString('GPSLatitude', (string) $served->getBody());
        self::assertStringNotContainsString('secret', (string) $served->getBody());
    }

    public function testPhpAndHtmlUploadsAreRejected(): void
    {
        $h = new HttpHarness();
        $h->installAndLogin();
        foreach (['<?php phpinfo();' => 'x.php', '<html><script>alert(1)</script>' => 'x.html', '<svg onload=alert(1)>' => 'x.svg'] as $bytes => $name) {
            $h->get('/admin/media');
            self::assertSame(422, $h->upload('/admin/media', $bytes, $name, 'image/png')->getStatusCode());
        }
        self::assertSame('', self::uploadedId($h));
    }

    public function testUploadRequiresAuthenticationAndCsrf(): void
    {
        $h = new HttpHarness();
        $h->installAndLogin();
        $h->get('/admin/media');
        self::assertSame(403, $h->upload('/admin/media', MediaFixtures::image(), 'a.jpg', withToken: false)->getStatusCode());

        $anon = $h->fresh();
        $anon->get('/admin/login');
        $res = $anon->upload('/admin/media', MediaFixtures::image(), 'a.jpg');
        self::assertSame(302, $res->getStatusCode());
        self::assertSame('', self::uploadedId($h));
    }

    public function testMediaUrlsCannotTraverse(): void
    {
        $h = new HttpHarness();
        $h->installAndLogin();
        foreach (['/media/..%2f..%2fvar%2fconfig.json', '/media/../config.json', '/media/' . str_repeat('0', 32), '/media/ABC', '/media/' . str_repeat('a', 32) . '.php'] as $url) {
            self::assertSame(404, $h->fresh()->get($url)->getStatusCode(), $url);
        }
    }

    public function testPdfIsServedAsAttachment(): void
    {
        $h = new HttpHarness();
        $h->installAndLogin();
        $h->get('/admin/media');
        $h->upload('/admin/media', MediaFixtures::pdf(), 'doc.pdf', 'application/pdf');
        $id = self::uploadedId($h);
        $served = $h->fresh()->get('/media/' . $id);
        self::assertStringStartsWith('attachment', $served->getHeaderLine('Content-Disposition'));
        self::assertSame('application/pdf', $served->getHeaderLine('Content-Type'));
    }

    public function testImageBlockAcceptsOnlyExistingMedia(): void
    {
        $h = new HttpHarness();
        $h->installAndLogin();
        $h->get('/admin/media');
        $h->upload('/admin/media', MediaFixtures::image('png'), 'pic.png', 'image/png');
        $id = self::uploadedId($h);

        $h->get('/admin/entries/new');
        $bad = $h->post('/admin/entries', ['title' => 'T', 'slug' => 'bad', 'blocks' => [['type' => 'image', 'media' => str_repeat('f', 32), 'text' => 'x']]]);
        self::assertSame(422, $bad->getStatusCode());
        $h->get('/admin/entries/new');
        $evil = $h->post('/admin/entries', ['title' => 'T', 'slug' => 'evil', 'blocks' => [['type' => 'image', 'media' => 'javascript:alert(1)', 'text' => 'x']]]);
        self::assertSame(422, $evil->getStatusCode());

        $h->get('/admin/entries/new');
        $ok = $h->post('/admin/entries', ['title' => 'Pic', 'slug' => 'pic', 'blocks' => [['type' => 'image', 'media' => $id, 'text' => 'A "red" square']]]);
        self::assertSame(303, $ok->getStatusCode());
        preg_match('~/admin/entries/([0-9a-f-]+)/edit~', $ok->getHeaderLine('Location'), $m);
        $h->get("/admin/entries/{$m[1]}/edit");
        $h->post("/admin/entries/{$m[1]}/publish", []);
        $page = (string) $h->fresh()->get('/en/pic')->getBody();
        self::assertStringContainsString('<img src="/media/' . $id . '" alt="A &quot;red&quot; square"', $page);
    }
}
