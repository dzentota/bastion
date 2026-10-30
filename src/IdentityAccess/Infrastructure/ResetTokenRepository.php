<?php
declare(strict_types=1);

namespace Bastion\IdentityAccess\Infrastructure;

use Bastion\IdentityAccess\Domain\{AccountId, ResetToken};
use Bastion\Infrastructure\Database\Row;
use SecureDb\Db;

final class ResetTokenRepository
{
    public function __construct(private readonly Db $db)
    {
    }

    public function store(ResetToken $token, AccountId $account, int $now, int $ttl): void
    {
        $this->db->insert('?_password_resets', [
            'selector' => $token->selector(),
            'verifier_hash' => $token->verifierHash(),
            'account_id' => $account->toNative(),
            'created_at' => $now,
            'expires_at' => $now + $ttl,
            'used' => 0,
        ]);
    }

    /** Аккаунт, которому принадлежит действующий токен, или null. */
    public function accountFor(ResetToken $token, int $now): ?string
    {
        $row = $this->db->selectRow('SELECT * FROM ?_password_resets WHERE selector = ?', $token->selector());
        if (!$row) {
            return null;
        }
        $r = Row::of($row);
        if ($r->int('used') !== 0 || $r->int('expires_at') < $now || !hash_equals($r->str('verifier_hash'), $token->verifierHash())) {
            return null;
        }
        return $r->str('account_id');
    }

    /** Гасит все токены аккаунта (после использования или при выдаче нового). */
    public function invalidateFor(string $accountId): void
    {
        $this->db->query('UPDATE ?_password_resets SET used = 1 WHERE account_id = ? AND used = 0', $accountId);
    }

    public function countIssuedSince(string $accountId, int $since): int
    {
        return Row::of($this->db->selectRow(
            'SELECT COUNT(*) AS n FROM ?_password_resets WHERE account_id = ? AND created_at > ?', $accountId, $since,
        ))->int('n');
    }
}
