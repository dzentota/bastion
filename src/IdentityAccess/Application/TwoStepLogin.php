<?php
declare(strict_types=1);

namespace Bastion\IdentityAccess\Application;

use Bastion\Audit\Domain\{AuditAction, AuditTrail};
use Bastion\IdentityAccess\Domain\{Account, AccountId};
use Bastion\IdentityAccess\Infrastructure\AccountRepository;
use Bastion\SecurityMonitoring\Domain\{ActorKey, AppSensor, DetectionPoint, ResponseAction};
use Dzentota\Identity\Authenticator;
use Dzentota\Session\Middleware\SessionMiddleware;
use Dzentota\Session\SessionManager;
use OTPHP\TOTP;
use ParagonIE\HiddenString\HiddenString;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ServerRequestInterface;
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};

/**
 * Вход: пароль → (обязательный для Admin/Editor) TOTP → аутентифицированная сессия.
 * Abuser stories: credential-stuffing, session-hijack.
 */
#[AssetId('bastion-app')]
final class TwoStepLogin
{
    /** Версия учётных данных, к которой привязана сессия (см. RequireStaff). */
    public const CREDENTIALS_VERSION = 'credentials_version';
    private const PENDING = 'mfa_pending';
    private const PENDING_AT = 'mfa_pending_at';
    private const ENROLL_SECRET = 'mfa_enroll_secret';
    private const PENDING_TTL = 300;

    public function __construct(
        private readonly PasswordVerifier $passwords,
        private readonly AccountRepository $accounts,
        private readonly AppSensor $sensor,
        private readonly ClockInterface $clock,
        private readonly AuditTrail $audit,
    ) {
    }

    #[AbuserStory('credential-stuffing')]
    #[Mitigation(cwe: 'CWE-307', description: 'AppSensor AE2/AE3: per-account temporary lock and per-IP throttle')]
    #[Mitigation(cwe: 'CWE-308', description: 'Second factor (TOTP, replay-protected) mandatory for Admin and Editor')]
    public function password(ServerRequestInterface $request, SessionManager $session, string $username, #[\SensitiveParameter] string $password): LoginOutcome
    {
        $ip = ActorKey::ip($this->ip($request));
        $acct = ActorKey::account(mb_strtolower(trim($username)));
        if ($this->sensor->isActive(ResponseAction::Throttle, $ip)) {
            return LoginOutcome::Throttled;
        }
        $this->sensor->event(DetectionPoint::AE3, $ip); // частота попыток входа с одного источника
        if ($this->sensor->isActive(ResponseAction::TemporaryLock, $acct)) {
            return LoginOutcome::Rejected;
        }

        $account = $this->passwords->verify($username, $password);
        if ($account === null) {
            $this->sensor->event(DetectionPoint::AE2, $acct);
            return LoginOutcome::Rejected;
        }

        // Пароль верен, но сессия ещё НЕ аутентифицирована.
        $session->regenerateId();
        $session->set(self::PENDING, $account->getId());
        $session->set(self::PENDING_AT, $this->now());

        if ($account->hasTotp) {
            return LoginOutcome::SecondFactorRequired;
        }
        if ($account->role->requiresSecondFactor()) {
            return LoginOutcome::SecondFactorEnrollmentRequired;
        }
        $this->complete($request, $session, $account);
        return LoginOutcome::Authenticated;
    }

    public function pendingAccount(SessionManager $session): ?Account
    {
        $id = $session->get(self::PENDING);
        $at = (int) $session->get(self::PENDING_AT, 0);
        if (!is_string($id) || $this->now() - $at > self::PENDING_TTL) {
            return null;
        }
        return $this->accounts->find($id);
    }

    public function totp(ServerRequestInterface $request, SessionManager $session, string $code): bool
    {
        $account = $this->pendingAccount($session);
        if ($account === null || !$account->hasTotp) {
            return false;
        }
        $secret = $this->accounts->totpSecret($account->id);
        $step = $secret ? $this->matchingStep($secret, $code) : null;
        if ($step === null || !$this->accounts->consumeTotpStep($account->id, $step)) {
            $this->sensor->event(DetectionPoint::AE12, ActorKey::account($account->username->toNative()), ActorKey::ip($this->ip($request)));
            return false;
        }
        $this->complete($request, $session, $account);
        return true;
    }

    /** Начало подключения TOTP: секрет живёт только в сессии до подтверждения кодом. */
    public function startEnrollment(SessionManager $session): ?TOTP
    {
        $account = $this->pendingAccount($session);
        if ($account === null || $account->hasTotp) {
            return null;
        }
        $secret = $session->get(self::ENROLL_SECRET);
        $totp = is_string($secret) ? TOTP::createFromSecret($secret, $this->clock) : TOTP::generate($this->clock);
        $session->set(self::ENROLL_SECRET, $totp->getSecret());
        $totp->setLabel($account->username->toNative());
        $totp->setIssuer('Bastion');
        return $totp;
    }

    public function confirmEnrollment(ServerRequestInterface $request, SessionManager $session, string $code): bool
    {
        $account = $this->pendingAccount($session);
        $secret = $session->get(self::ENROLL_SECRET);
        if ($account === null || $account->hasTotp || !is_string($secret)) {
            return false;
        }
        $step = $this->matchingStep(new HiddenString($secret), $code);
        if ($step === null) {
            $this->sensor->event(DetectionPoint::AE12, ActorKey::ip($this->ip($request)));
            return false;
        }
        $this->accounts->saveTotpSecret($account->id, new HiddenString($secret));
        $this->accounts->consumeTotpStep($account->id, $step);
        $session->remove(self::ENROLL_SECRET);
        $this->audit->record(AuditAction::SecondFactorEnrolled, $account->getId(), null, $this->ip($request));
        $this->complete($request, $session, $this->accounts->find($account->getId()) ?? $account);
        return true;
    }

    public function logout(ServerRequestInterface $request, SessionManager $session): void
    {
        $actor = $session->get(Authenticator::AUTH_USER_ID);
        $session->destroy();
        $this->audit->record(AuditAction::Logout, is_string($actor) ? $actor : null, null, $this->ip($request));
    }

    #[AbuserStory('session-hijack')]
    #[Mitigation(cwe: 'CWE-384', description: 'Session id regenerated after password and again after the second factor')]
    private function complete(ServerRequestInterface $request, SessionManager $session, Account $account): void
    {
        $session->remove(self::PENDING);
        $session->remove(self::PENDING_AT);
        // dzentota/identity: регенерирует id сессии и помечает её аутентифицированной.
        (new Authenticator($this->accounts, $session, AccountRepository::ARGON))
            ->completeLogin($request->withAttribute(SessionMiddleware::SESSION_ATTRIBUTE, $session), $account);
        $session->set(self::CREDENTIALS_VERSION, $this->accounts->credentialsVersion($account->getId()));
        $this->audit->record(AuditAction::LoginSucceeded, $account->getId(), null, $this->ip($request));
    }

    /** @return int|null номер шага TOTP, которому соответствует код (окно ±1 шаг) */
    private function matchingStep(HiddenString $secret, string $code): ?int
    {
        if (!preg_match('/^\d{6}$/', $code)) {
            return null;
        }
        $totp = TOTP::createFromSecret($secret->getString(), $this->clock);
        $now = $this->now();
        foreach ([0, -1, 1] as $offset) {
            $t = $now + $offset * $totp->getPeriod();
            if (hash_equals($totp->at($t), $code)) {
                return intdiv($t, $totp->getPeriod());
            }
        }
        return null;
    }

    private function now(): int
    {
        return $this->clock->now()->getTimestamp();
    }

    private function ip(ServerRequestInterface $request): string
    {
        // Без доверенных прокси берём только REMOTE_ADDR (X-Forwarded-For подделывается).
        return (string) ($request->getServerParams()['REMOTE_ADDR'] ?? 'unknown');
    }
}
