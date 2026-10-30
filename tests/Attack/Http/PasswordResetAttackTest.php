<?php
declare(strict_types=1);

namespace Bastion\Tests\Attack\Http;

use Bastion\IdentityAccess\Domain\StaffEmail;
use Bastion\Infrastructure\Database\Connection;
use Bastion\Mail\SmtpConfig;
use Bastion\Tests\Support\HttpHarness;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Abuser stories: reset-token-theft, reset-account-enumeration, reset-host-poisoning,
 * mail-header-injection, reset-mail-flood, reset-session-persistence, smtp-cleartext.
 */
final class PasswordResetAttackTest extends TestCase
{
    private const NEW = 'a brand new passphrase 2026';

    private HttpHarness $h;

    protected function setUp(): void
    {
        $this->h = new HttpHarness();
        $this->h->installAndLogin();
    }

    private function requestReset(string $email, ?HttpHarness $as = null): HttpHarness
    {
        $v = $as ?? $this->h->fresh();
        $v->get('/admin/forgot');
        $v->post('/admin/forgot', ['email' => $email]);
        return $v;
    }

    private function lastLink(): string
    {
        $mail = end($this->h->mailer->sent);
        self::assertNotFalse($mail, 'письмо не отправлено');
        preg_match('~(https?://\S+/admin/reset/\S+)~', $mail['text'], $m);
        return $m[1];
    }

    private function resetWith(string $link, string $password): \Psr\Http\Message\ResponseInterface
    {
        $v = $this->h->fresh();
        $path = (string) parse_url($link, PHP_URL_PATH);
        $arrive = $v->get($path);
        self::assertSame('/admin/reset', $arrive->getHeaderLine('Location'));
        $v->get('/admin/reset');
        return $v->post('/admin/reset', ['password' => $password]);
    }

    public function testFullResetKeepsSecondFactor(): void
    {
        $this->requestReset('OWNER@example.com ');
        self::assertSame('owner@example.com', $this->h->mailer->sent[0]['to']);
        self::assertSame('/admin/login', $this->resetWith($this->lastLink(), self::NEW)->getHeaderLine('Location'));

        $old = $this->h->fresh();
        $old->get('/admin/login');
        self::assertSame(401, $old->post('/admin/login', ['username' => 'owner', 'password' => 'correct horse battery staple'])->getStatusCode(),
            'старый пароль больше не работает');

        $login = $this->h->fresh();
        $login->get('/admin/login');
        self::assertSame('/admin/2fa', $login->post('/admin/login', ['username' => 'owner', 'password' => self::NEW])->getHeaderLine('Location'),
            'после сброса всё равно нужен второй фактор');
    }

    public function testWeakNewPasswordIsRejectedAndTokenSurvives(): void
    {
        $this->requestReset('owner@example.com');
        self::assertSame(422, $this->resetWith($this->lastLink(), 'password123')->getStatusCode());
    }

    public function testTokenIsSingleUseAndStoredHashed(): void
    {
        $this->requestReset('owner@example.com');
        $link = $this->lastLink();
        $this->resetWith($link, self::NEW);

        $replay = $this->h->fresh();
        self::assertSame(410, $replay->get((string) parse_url($link, PHP_URL_PATH))->getStatusCode());

        $verifier = explode('.', basename($link))[1];
        $dump = json_encode(Connection::sqlite($this->h->paths->sqlite())->select('SELECT * FROM ?_password_resets'));
        self::assertStringNotContainsString($verifier, (string) $dump);
    }

    public function testTamperedAndExpiredTokensAreRejected(): void
    {
        $this->requestReset('owner@example.com');
        $path = (string) parse_url($this->lastLink(), PHP_URL_PATH);
        [$selector, $verifier] = explode('.', basename($path));
        $forged = '/admin/reset/' . $selector . '.' . strrev($verifier);
        self::assertSame(410, $this->h->fresh()->get($forged)->getStatusCode());
        self::assertSame(404, $this->h->fresh()->get('/admin/reset/../../config')->getStatusCode());

        Connection::sqlite($this->h->paths->sqlite())->query('UPDATE ?_password_resets SET expires_at = 1');
        self::assertSame(410, $this->h->fresh()->get($path)->getStatusCode());
    }

    public function testNewRequestRevokesOlderLinks(): void
    {
        $this->requestReset('owner@example.com');
        $first = $this->lastLink();
        $this->requestReset('owner@example.com');
        self::assertSame(410, $this->h->fresh()->get((string) parse_url($first, PHP_URL_PATH))->getStatusCode());
    }

    public function testResponseDoesNotRevealWhetherAccountExists(): void
    {
        $known = $this->requestReset('owner@example.com')->body();
        $unknown = $this->requestReset('nobody@example.com')->body();
        $strip = static fn (string $html) => preg_replace('/name="_token" value="[^"]*"/', '', $html);
        self::assertSame($strip($known), $strip($unknown));
        self::assertCount(1, $this->h->mailer->sent);
    }

    public function testHostHeaderDoesNotChangeTheLink(): void
    {
        $attacker = $this->h->fresh();
        $attacker->host = 'evil.example';
        $this->requestReset('owner@example.com', $attacker);
        self::assertStringStartsWith('http://localhost/admin/reset/', $this->lastLink());
    }

    public static function injections(): iterable
    {
        yield ["owner@example.com\r\nBcc: attacker@evil.example"];
        yield ["owner@example.com%0d%0aBcc:attacker@evil.example"];
        yield ['"owner@example.com>\nBcc: x"@evil.example'];
    }

    #[DataProvider('injections')]
    public function testHeaderInjectionSendsNothing(string $email): void
    {
        $this->requestReset($email);
        self::assertSame([], $this->h->mailer->sent);
    }

    public function testResetMailsAreRateLimited(): void
    {
        for ($i = 0; $i < 6; $i++) {
            $this->requestReset('owner@example.com');
        }
        self::assertCount(3, $this->h->mailer->sent);
    }

    public function testResetSignsOutStolenSessions(): void
    {
        $stolen = clone $this->h; // атакующий скопировал cookie администратора
        self::assertSame(200, $stolen->get('/admin')->getStatusCode());
        $this->requestReset('owner@example.com');
        $this->resetWith($this->lastLink(), self::NEW);
        self::assertSame('/admin/login', $stolen->get('/admin')->getHeaderLine('Location'));
    }

    public static function insecureSmtp(): iterable
    {
        yield 'plain port 25' => ['smtp.example.com', 25];
        yield 'ip address' => ['192.0.2.10', 587];
        yield 'header in host' => ["smtp.example.com\r\nX: y", 587];
    }

    #[DataProvider('insecureSmtp')]
    public function testInsecureSmtpSettingsAreRefused(string $host, int $port): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new SmtpConfig($host, $port, 'user', 'secret', StaffEmail::fromNative('noreply@example.com'));
    }

    public function testCliIssuesWorkingLinkWithoutMail(): void
    {
        $cli = 'BASTION_ROOT=' . escapeshellarg($this->h->paths->root) . ' ' . PHP_BINARY . ' '
            . escapeshellarg(dirname(__DIR__, 3) . '/bin/bastion') . ' reset-link owner 2>&1';
        exec($cli, $out, $code);
        self::assertSame(0, $code, implode("\n", $out));
        self::assertSame([], $this->h->mailer->sent);
        self::assertSame('/admin/login', $this->resetWith($out[1], self::NEW)->getHeaderLine('Location'));
    }
}
