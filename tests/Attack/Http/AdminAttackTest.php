<?php
declare(strict_types=1);

namespace Bastion\Tests\Attack\Http;

use Bastion\IdentityAccess\Domain\{NewPassword, Role, Username};
use Bastion\IdentityAccess\Infrastructure\AccountRepository;
use Bastion\Infrastructure\Database\Connection;
use Bastion\Tests\Support\HttpHarness;
use ParagonIE\Halite\KeyFactory;
use PHPUnit\Framework\TestCase;

/** Abuser stories: csrf-publish, privilege-escalation, sqli-content, session-hijack. */
final class AdminAttackTest extends TestCase
{
    private static function createPost(HttpHarness $h, string $slug): string
    {
        $h->get('/admin/entries/new');
        $res = $h->post('/admin/entries', ['title' => 'T', 'slug' => $slug, 'blocks' => [['type' => 'paragraph', 'text' => 'x']]]);
        self::assertSame(303, $res->getStatusCode());
        preg_match('~/admin/entries/([0-9a-f-]+)/edit~', $res->getHeaderLine('Location'), $m);
        return $m[1];
    }

    public function testPublishWithoutCsrfTokenIsRejected(): void
    {
        $h = new HttpHarness();
        $h->installAndLogin();
        $id = self::createPost($h, 'draft-post');
        self::assertSame(403, $h->post("/admin/entries/{$id}/publish", [], withToken: false)->getStatusCode());
        self::assertSame(403, $h->post("/admin/entries/{$id}/publish", ['_token' => 'forged'], withToken: false)->getStatusCode());
        self::assertSame(404, $h->fresh()->get('/draft-post')->getStatusCode());
    }

    public function testAnonymousCannotReachAdminActions(): void
    {
        $h = new HttpHarness();
        $h->installAndLogin();
        $id = self::createPost($h, 'p');
        $anon = $h->fresh();
        $anon->get('/admin/login');
        $res = $anon->post("/admin/entries/{$id}/publish", []);
        self::assertSame(302, $res->getStatusCode());
        self::assertSame('/admin/login', $res->getHeaderLine('Location'));
    }

    public function testAuthorCannotPublishOrEditOthers(): void
    {
        $h = new HttpHarness();
        $h->installAndLogin();
        $adminPost = self::createPost($h, 'admin-post');

        $db = Connection::sqlite($h->paths->sqlite());
        $u = Username::fromNative('writer');
        (new AccountRepository($db, KeyFactory::loadEncryptionKey($h->paths->encryptionKey())))
            ->create($u, NewPassword::forUser('another long passphrase here', $u), Role::Author);

        $author = $h->fresh();
        $author->get('/admin/login');
        self::assertSame('/admin', $author->post('/admin/login', ['username' => 'writer', 'password' => 'another long passphrase here'])->getHeaderLine('Location'));

        self::assertSame(404, $author->get("/admin/entries/{$adminPost}/edit")->getStatusCode());
        $own = self::createPost($author, 'author-post');
        $author->get("/admin/entries/{$own}/edit");
        self::assertSame(403, $author->post("/admin/entries/{$own}/publish", [])->getStatusCode());
        self::assertSame(404, $author->fresh()->get('/author-post')->getStatusCode());
    }

    public function testSqlInjectionThroughSlugIsImpossible(): void
    {
        $h = new HttpHarness();
        $h->installAndLogin();
        foreach (["x'%20OR%20'1'='1", 'x%22%3B--', '..%2fadmin'] as $slug) {
            self::assertSame(404, $h->fresh()->get('/' . $slug)->getStatusCode());
        }
        $h->get('/admin/entries/new');
        self::assertSame(422, $h->post('/admin/entries', ['title' => 'T', 'slug' => "a' OR 1=1 --", 'blocks' => []])->getStatusCode());
    }

    public function testLogoutDestroysServerSideSession(): void
    {
        $h = new HttpHarness();
        $h->installAndLogin();
        $stolen = clone $h; // атакующий скопировал cookie
        $h->get('/admin');
        $h->post('/admin/logout', []);
        self::assertSame(302, $stolen->get('/admin')->getStatusCode());
    }
}
