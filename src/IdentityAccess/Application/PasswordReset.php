<?php
declare(strict_types=1);

namespace Bastion\IdentityAccess\Application;

use Bastion\Audit\Domain\{AuditAction, AuditTrail};
use Bastion\IdentityAccess\Domain\{Account, NewPassword, ResetToken, SiteUrl, StaffEmail};
use Bastion\IdentityAccess\Infrastructure\{AccountRepository, ResetTokenRepository};
use Bastion\Mail\Mailer;
use Bastion\SecurityMonitoring\Domain\{ActorKey, AppSensor, DetectionPoint};
use Bastion\Shared\Application\AfterResponse;
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};
use Psr\Clock\ClockInterface;

/**
 * Сброс пароля по email (ADR-0009). Второй фактор сброс не затрагивает:
 * после смены пароля вход по-прежнему требует TOTP.
 */
#[AssetId('bastion-app')]
#[AbuserStory('reset-token-theft')]
#[Mitigation(cwe: 'CWE-640', description: 'Split token (128-bit selector + 256-bit verifier stored as SHA-256), 30 min TTL, single use, all tokens revoked on use or new request; token moved from URL into session immediately; 2FA still required after reset')]
#[AbuserStory('reset-account-enumeration')]
#[Mitigation(cwe: 'CWE-204', description: 'Identical response for known and unknown emails; mail sent after the response is flushed so timing does not reveal existence')]
#[AbuserStory('reset-host-poisoning')]
#[Mitigation(cwe: 'CWE-644', description: 'Reset links are built only from the configured canonical SiteUrl, never from the Host header')]
#[AbuserStory('reset-mail-flood')]
#[Mitigation(cwe: 'CWE-799', description: 'At most 3 reset mails per account per hour; per-IP AppSensor UT2 throttle on repeated requests')]
#[AbuserStory('reset-session-persistence')]
#[Mitigation(cwe: 'CWE-613', description: 'Password change increments credentials_version; RequireStaff rejects sessions bound to an older version')]
final class PasswordReset
{
    public const TTL = 1800;
    private const MAX_PER_HOUR = 3;

    public function __construct(
        private readonly AccountRepository $accounts,
        private readonly ResetTokenRepository $tokens,
        private readonly Mailer $mailer,
        private readonly AfterResponse $after,
        private readonly SiteUrl $site,
        private readonly AppSensor $sensor,
        private readonly AuditTrail $audit,
        private readonly ClockInterface $clock,
    ) {
    }

    public function isAvailable(): bool
    {
        return $this->mailer->isConfigured();
    }

    /** Ответ одинаков всегда: ничего не возвращает и ничего не бросает наружу. */
    public function request(string $rawEmail, string $ip): void
    {
        $this->sensor->event(DetectionPoint::UT2, ActorKey::ip($ip));
        $email = StaffEmail::fromInput($rawEmail);
        $account = $email ? $this->accounts->findByEmail($email) : null;
        if ($account === null || $email === null || !$this->mailer->isConfigured()) {
            return;
        }
        $now = $this->clock->now()->getTimestamp();
        if ($this->tokens->countIssuedSince($account->getId(), $now - 3600) >= self::MAX_PER_HOUR) {
            return;
        }
        $this->tokens->invalidateFor($account->getId());
        $link = $this->issueLink($account, $now);
        $this->audit->record(AuditAction::PasswordResetRequested, $account->getId(), null, $ip);
        $this->after->defer(fn () => $this->mailer->send($email, 'Reset your Bastion password',
            "Someone asked to reset the password for the account \"{$account->username->toNative()}\".\n\n"
            . "To choose a new password, open this link within 30 minutes:\n{$link}\n\n"
            . "If it wasn't you, ignore this email: your password stays the same.\n"
            . "You will still need your two-factor code to sign in.\n"));
    }

    /** Выдача ссылки администратором через CLI (Emergency Access) — без почты. */
    public function issueLinkFor(Account $account): string
    {
        $this->tokens->invalidateFor($account->getId());
        $this->audit->record(AuditAction::PasswordResetRequested, 'cli', $account->getId(), 'cli');
        return $this->issueLink($account, $this->clock->now()->getTimestamp());
    }

    public function accountFor(ResetToken $token): ?Account
    {
        $id = $this->tokens->accountFor($token, $this->clock->now()->getTimestamp());
        return $id === null ? null : $this->accounts->find($id);
    }

    public function complete(ResetToken $token, NewPassword $password, string $ip): bool
    {
        $account = $this->accountFor($token);
        if ($account === null) {
            return false;
        }
        $this->tokens->invalidateFor($account->getId());
        $this->accounts->changePassword($account->id, $password);
        $this->audit->record(AuditAction::PasswordChanged, $account->getId(), null, $ip);
        return true;
    }

    private function issueLink(Account $account, int $now): string
    {
        $token = ResetToken::issue();
        $this->tokens->store($token, $account->id, $now, self::TTL);
        return $this->site->link('/admin/reset/' . $token->toNative());
    }
}
