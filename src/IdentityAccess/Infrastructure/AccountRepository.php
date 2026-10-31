<?php
declare(strict_types=1);

namespace Bastion\IdentityAccess\Infrastructure;

use Bastion\IdentityAccess\Domain\{Account, AccountId, NewPassword, Role, StaffEmail, Username};
use Bastion\Infrastructure\Database\Row;
use Dzentota\Identity\CredentialStore;
use Dzentota\Identity\Identity;
use ParagonIE\Halite\Symmetric\{Crypto, EncryptionKey};
use ParagonIE\HiddenString\HiddenString;
use SecureDb\Db;

/**
 * Хранилище учётных записей + реализация CredentialStore для dzentota/identity.
 * TOTP-секреты шифруются Halite (ADR-0014).
 */
final class AccountRepository implements CredentialStore
{
    public const ARGON = ['memory_cost' => 65536, 'time_cost' => 4, 'threads' => 1];

    public function __construct(private readonly Db $db, private readonly EncryptionKey $key)
    {
    }

    public function create(Username $username, NewPassword $password, Role $role, ?StaffEmail $email = null): Account
    {
        $id = AccountId::generate();
        $this->db->insert('?_accounts', [
            'id' => $id,
            'email' => $email?->toNative(),
            'username' => $username,
            'password_hash' => password_hash($password->toNative(), PASSWORD_ARGON2ID, self::ARGON),
            'role' => $role->value,
            'created_at' => gmdate('c'),
        ]);
        return new Account($id, $username, $role, false);
    }

    public function findByEmail(StaffEmail $email): ?Account
    {
        $id = $this->db->selectCell('SELECT id FROM ?_accounts WHERE email = ?', $email->toNative());
        return is_string($id) ? $this->find($id) : null;
    }

    public function findByUsername(Username $username): ?Account
    {
        $id = $this->db->selectCell('SELECT id FROM ?_accounts WHERE username = ?', $username->toNative());
        return is_string($id) ? $this->find($id) : null;
    }

    public function changePassword(AccountId $id, NewPassword $password): void
    {
        $this->db->query(
            'UPDATE ?_accounts SET password_hash = ?, credentials_version = credentials_version + 1 WHERE id = ?',
            password_hash($password->toNative(), PASSWORD_ARGON2ID, self::ARGON), $id->toNative(),
        );
    }

    /** Версия учётных данных: растёт при каждой смене пароля. Сессии со старой версией недействительны. */
    public function credentialsVersion(string $id): int
    {
        $row = $this->db->selectRow('SELECT credentials_version FROM ?_accounts WHERE id = ?', $id);
        return $row ? Row::of($row)->int('credentials_version') : -1;
    }

    /** @return list<string> */
    public function usernames(): array
    {
        return array_values(array_filter(array_map(
            static fn (mixed $v) => is_string($v) ? $v : null,
            $this->db->selectCol('SELECT username FROM ?_accounts'),
        )));
    }

    public function count(): int
    {
        return (int) $this->db->selectCell('SELECT COUNT(*) FROM ?_accounts');
    }

    public function fetchByUsername(string $username): ?array
    {
        if (!Username::tryParse($username)) {
            return null;
        }
        $row = $this->db->selectRow('SELECT id, password_hash FROM ?_accounts WHERE username = ?', $username);
        return $row ? ['id' => $row['id'], 'hash' => $row['password_hash']] : null;
    }

    public function updateCredentials(string $userId, string $newHash): void
    {
        $this->db->update('?_accounts', ['password_hash' => $newHash], ['id' => $userId]);
    }

    public function fetchIdentity(string $userId): ?Identity
    {
        return $this->find($userId);
    }

    public function find(string $userId): ?Account
    {
        if (!AccountId::tryParse($userId, $id)) {
            return null;
        }
        // SELECT *: до миграции 0003 колонки locale нет, а вход нужен, чтобы её применить
        $row = $this->db->selectRow('SELECT * FROM ?_accounts WHERE id = ?', $id);
        if (!$row) {
            return null;
        }
        $locale = \Bastion\Content\Domain\Language::tryParse($row['locale'] ?? null, $l) ? $l : null;
        return new Account($id, Username::fromNative($row['username']), Role::from($row['role']), $row['totp_secret'] !== null, $locale);
    }

    public function setLocale(AccountId $id, \Bastion\Content\Domain\Language $lang): void
    {
        $this->db->update('?_accounts', ['locale' => $lang->toNative()], ['id' => $id->toNative()]);
    }

    public function saveTotpSecret(AccountId $id, HiddenString $secret): void
    {
        $this->db->update('?_accounts', ['totp_secret' => Crypto::encrypt($secret, $this->key)], ['id' => $id]);
    }

    /**
     * Атомарно фиксирует использованный шаг TOTP: повторное использование кода невозможно.
     * @return bool false, если шаг уже был использован (replay)
     */
    public function consumeTotpStep(AccountId $id, int $step): bool
    {
        return $this->db->query(
            'UPDATE ?_accounts SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?', $step, $id, $step,
        ) === 1;
    }

    public function totpSecret(AccountId $id): ?HiddenString
    {
        $enc = $this->db->selectCell('SELECT totp_secret FROM ?_accounts WHERE id = ?', $id);
        return is_string($enc) ? Crypto::decrypt($enc, $this->key) : null;
    }
}
