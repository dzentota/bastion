<?php
declare(strict_types=1);

namespace Bastion\Tests\Attack\Http;

use Bastion\IdentityAccess\Domain\{NewPassword, Role, Username};
use Bastion\IdentityAccess\Infrastructure\AccountRepository;
use Bastion\Infrastructure\Database\Connection;
use Bastion\Tests\Support\HttpHarness;
use ParagonIE\Halite\KeyFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Abuser stories: comment-xss, comment-spam-flood, comment-moderation-bypass,
 * commenter-deanonymisation, comment-impersonation.
 */
final class CommentAttackTest extends TestCase
{
    private HttpHarness $h;
    private string $entryId;

    protected function setUp(): void
    {
        $this->h = new HttpHarness();
        $this->h->installAndLogin();
        $this->h->get('/admin/entries/new');
        $res = $this->h->post('/admin/entries', ['title' => 'Post', 'slug' => 'post', 'blocks' => [['type' => 'paragraph', 'text' => 'x']]]);
        preg_match('~/admin/entries/([0-9a-f-]+)/edit~', $res->getHeaderLine('Location'), $m);
        $this->entryId = $m[1];
        $this->h->get("/admin/entries/{$this->entryId}/edit");
        $this->h->post("/admin/entries/{$this->entryId}/publish", []);
    }

    /** Метка времени, подписанная ключом сайта, "выданная" $ago секунд назад. */
    private function stamp(int $ago = 30): string
    {
        $secret = hash_hmac('sha256', 'bastion:honeypot', (string) file_get_contents($this->h->paths->cacheKey()), true);
        $ts = (string) (time() - $ago);
        return $ts . '.' . rtrim(strtr(base64_encode(hash_hmac('sha256', $ts, $secret, true)), '+/', '-_'), '=');
    }

    /** @param array<string, string> $extra */
    private function comment(string $author, string $body, array $extra = []): \Psr\Http\Message\ResponseInterface
    {
        $visitor = $this->h->fresh();
        return $visitor->post('/comments', $extra + ['entry' => $this->entryId, 'author' => $author, 'body' => $body, '_timestamp' => $this->stamp()], withToken: false);
    }

    private function moderateAll(string $action): void
    {
        $this->h->get('/admin/comments');
        preg_match_all('~/admin/comments/([0-9a-f]{32})/approve~', $this->h->body(), $m);
        foreach ($m[1] as $id) {
            $this->h->get('/admin/comments');
            $this->h->post("/admin/comments/{$id}/{$action}", []);
        }
    }

    public function testCommentIsHeldForModerationAndRenderedInert(): void
    {
        $payload = "<script>alert(1)</script>\n<img src=x onerror=alert(2)>";
        self::assertSame(200, $this->comment('Eve', $payload)->getStatusCode());
        self::assertStringNotContainsString('onerror', (string) $this->h->fresh()->get('/post')->getBody(), 'не опубликован до модерации');

        $this->h->get('/admin/comments');
        self::assertStringNotContainsString('<script>alert(1)', $this->h->body(), 'модератор видит экранированный текст');
        self::assertStringContainsString('&lt;script&gt;', $this->h->body());

        $this->moderateAll('approve');
        $page = (string) $this->h->fresh()->get('/post')->getBody();
        self::assertStringContainsString('&lt;img src=x onerror=alert(2)&gt;', $page);
        self::assertDoesNotMatchRegularExpression('/<(script|img)\b/i', $page);
    }

    public static function botSubmissions(): iterable
    {
        yield 'no timestamp' => [['_timestamp' => '']];
        yield 'unsigned timestamp' => [['_timestamp' => (string) (time() - 60)]];
        yield 'forged signature' => [['_timestamp' => (time() - 60) . '.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA']];
        yield 'honeypot filled' => [['website' => 'http://spam.example']];
    }

    #[DataProvider('botSubmissions')]
    public function testBotsAreBlocked(array $override): void
    {
        $visitor = $this->h->fresh();
        $res = $visitor->post('/comments', $override + ['entry' => $this->entryId, 'author' => 'Bot', 'body' => 'buy', '_timestamp' => $this->stamp()], withToken: false);
        self::assertSame(403, $res->getStatusCode());
        $this->h->get('/admin/comments');
        self::assertStringContainsString('Nothing to moderate', $this->h->body());
    }

    public function testInstantSubmissionIsBlocked(): void
    {
        self::assertSame(403, $this->comment('Bot', 'fast', ['_timestamp' => $this->stamp(0)])->getStatusCode());
    }

    public function testBurstFromOneSourceIsRateLimited(): void
    {
        for ($i = 0; $i < 5; $i++) {
            self::assertSame(200, $this->comment("Reader{$i}", "comment {$i}")->getStatusCode());
        }
        self::assertSame(422, $this->comment('Reader6', 'one more')->getStatusCode());
    }

    public function testLinkSpamSkipsTheModerationQueue(): void
    {
        $this->comment('Spammer', 'http://a.example http://b.example www.c.example');
        $this->h->get('/admin/comments');
        self::assertStringNotContainsString('Spammer', $this->h->body());
    }

    public function testIpAndEmailAreNotStored(): void
    {
        $this->comment('Alice', 'hello');
        $rows = Connection::sqlite($this->h->paths->sqlite())->select('SELECT * FROM ?_comments');
        $dump = json_encode($rows, JSON_THROW_ON_ERROR);
        self::assertStringContainsString('hello', $dump);
        self::assertStringNotContainsString('198.51.100.10', $dump);
        self::assertStringNotContainsString('@', $dump);
    }

    public static function impersonations(): iterable
    {
        yield 'owner username' => ['owner'];
        yield 'case and dots' => ['O.W.N.E.R'];
        yield 'fullwidth admin' => ['ＡＤＭＩＮ'];
        yield 'bidi override' => ["\u{202E}renwo"];
        yield 'zero width' => ["own\u{200B}er"];
        yield 'leading space' => [' owner'];
    }

    #[DataProvider('impersonations')]
    public function testStaffNamesCannotBeImpersonated(string $name): void
    {
        self::assertSame(422, $this->comment($name, 'trust me')->getStatusCode());
    }

    public function testModerationRequiresCapabilityAndCsrf(): void
    {
        $this->comment('Alice', 'hello');
        $this->h->get('/admin/comments');
        preg_match('~/admin/comments/([0-9a-f]{32})/approve~', $this->h->body(), $m);
        $id = $m[1];

        self::assertSame(403, $this->h->post("/admin/comments/{$id}/approve", [], withToken: false)->getStatusCode());
        $anon = $this->h->fresh();
        $anon->get('/admin/login');
        self::assertSame('/admin/login', $anon->post("/admin/comments/{$id}/approve", [])->getHeaderLine('Location'));

        $db = Connection::sqlite($this->h->paths->sqlite());
        $u = Username::fromNative('writer');
        (new AccountRepository($db, KeyFactory::loadEncryptionKey($this->h->paths->encryptionKey())))
            ->create($u, NewPassword::forUser('another long passphrase here', $u), Role::Author);
        $author = $this->h->fresh();
        $author->get('/admin/login');
        $author->post('/admin/login', ['username' => 'writer', 'password' => 'another long passphrase here']);
        self::assertSame(403, $author->get('/admin/comments')->getStatusCode());
        $author->get('/admin');
        self::assertSame(403, $author->post("/admin/comments/{$id}/approve", [])->getStatusCode());

        self::assertStringNotContainsString('hello', (string) $this->h->fresh()->get('/post')->getBody());
    }
}
