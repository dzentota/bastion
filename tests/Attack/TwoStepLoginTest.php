<?php
declare(strict_types=1);

namespace Bastion\Tests\Attack;

use Bastion\IdentityAccess\Application\{LoginOutcome, PasswordVerifier, TwoStepLogin};
use Bastion\IdentityAccess\Domain\{NewPassword, Role, Username};
use Bastion\IdentityAccess\Infrastructure\AccountRepository;
use Bastion\SecurityMonitoring\Infrastructure\DbAppSensor;
use Bastion\Tests\Support\{Database, FrozenClock};
use dzentota\Router\Middleware\Cache\ArrayCache;
use Dzentota\Identity\Authenticator;
use Dzentota\Session\Cookie\CookieManager;
use Dzentota\Session\SessionManager;
use Dzentota\Session\Storage\CacheStorage;
use Nyholm\Psr7\ServerRequest;
use OTPHP\TOTP;
use ParagonIE\Halite\KeyFactory;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

/** Abuser stories: credential-stuffing, session-hijack (обход 2FA), TOTP replay. */
final class TwoStepLoginTest extends TestCase
{
    private const PASS = 'correct horse battery staple';
    private FrozenClock $clock;
    private AccountRepository $accounts;
    private TwoStepLogin $login;

    protected function setUp(): void
    {
        $db = Database::memory();
        $this->clock = new FrozenClock();
        $this->accounts = new AccountRepository($db, KeyFactory::generateEncryptionKey());
        $this->login = new TwoStepLogin(new PasswordVerifier($this->accounts), $this->accounts,
            new DbAppSensor($db, $this->clock, new NullLogger()), $this->clock, new \Bastion\Tests\Support\RecordingAuditTrail());
        $u = Username::fromNative('owner');
        $this->accounts->create($u, NewPassword::forUser(self::PASS, $u), Role::Admin);
    }

    private function session(): SessionManager
    {
        $s = new SessionManager(new CacheStorage(new ArrayCache()), new CookieManager());
        $s->start(new ServerRequest('GET', '/'));
        return $s;
    }

    private function request(string $ip = '203.0.113.5'): ServerRequest
    {
        return new ServerRequest('POST', '/admin/login', [], null, '1.1', ['REMOTE_ADDR' => $ip]);
    }

    public function testAdminWithoutTotpMustEnrollAndIsNotAuthenticatedBeforeThat(): void
    {
        $s = $this->session();
        self::assertSame(LoginOutcome::SecondFactorEnrollmentRequired, $this->login->password($this->request(), $s, 'owner', self::PASS));
        self::assertNull($s->get(Authenticator::AUTH_USER_ID), 'пароль сам по себе не аутентифицирует админа');

        $totp = $this->login->startEnrollment($s);
        self::assertTrue($this->login->confirmEnrollment($this->request(), $s, $totp->at($this->clock->now()->getTimestamp())));
        self::assertNotNull($s->get(Authenticator::AUTH_USER_ID));
    }

    public function testTotpCodeCannotBeReplayed(): void
    {
        $s = $this->session();
        $this->login->password($this->request(), $s, 'owner', self::PASS);
        $totp = $this->login->startEnrollment($s);
        $code = $totp->at($this->clock->now()->getTimestamp());
        $this->login->confirmEnrollment($this->request(), $s, $code);

        $s2 = $this->session();
        self::assertSame(LoginOutcome::SecondFactorRequired, $this->login->password($this->request(), $s2, 'owner', self::PASS));
        self::assertFalse($this->login->totp($this->request(), $s2, $code), 'тот же код второй раз не принимается');
        self::assertNull($s2->get(Authenticator::AUTH_USER_ID));

        $this->clock->advance(30);
        self::assertTrue($this->login->totp($this->request(), $s2, $totp->at($this->clock->now()->getTimestamp())));
    }

    public function testPendingSecondFactorExpires(): void
    {
        $s = $this->session();
        $this->login->password($this->request(), $s, 'owner', self::PASS);
        $this->clock->advance(301);
        self::assertNull($this->login->startEnrollment($s));
    }

    public function testCredentialStuffingLocksAccountEvenForCorrectPassword(): void
    {
        for ($i = 0; $i < 5; $i++) {
            self::assertSame(LoginOutcome::Rejected, $this->login->password($this->request('203.0.113.' . $i), $this->session(), 'owner', 'wrong-' . $i));
        }
        self::assertSame(LoginOutcome::Rejected, $this->login->password($this->request('198.51.100.7'), $this->session(), 'owner', self::PASS));
    }

    public function testUnknownUserLooksLikeWrongPassword(): void
    {
        self::assertSame(LoginOutcome::Rejected, $this->login->password($this->request(), $this->session(), 'nobody', self::PASS));
    }

    public function testSingleSourceIsThrottled(): void
    {
        for ($i = 0; $i < 20; $i++) {
            $this->login->password($this->request(), $this->session(), "user{$i}", 'x');
        }
        self::assertSame(LoginOutcome::Throttled, $this->login->password($this->request(), $this->session(), 'owner', self::PASS));
    }
}
