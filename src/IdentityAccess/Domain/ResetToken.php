<?php
declare(strict_types=1);

namespace Bastion\IdentityAccess\Domain;

use dzentota\TypedValue\Typed;
use dzentota\TypedValue\TypedValue;
use dzentota\TypedValue\ValidationResult;

/**
 * Split-токен сброса пароля: "<selector>.<verifier>".
 * selector (128 бит, hex) — ключ поиска; verifier (256 бит, base64url) хранится только хэшем,
 * так что дамп БД не даёт рабочих токенов, а поиск по selector не даёт timing-утечки verifier.
 * @implements Typed<string>
 */
final class ResetToken implements Typed
{
    /** @use TypedValue<string> */
    use TypedValue;

    public static function validate($value): ValidationResult
    {
        $r = new ValidationResult();
        if (!is_string($value) || !preg_match('/^[0-9a-f]{32}\.[A-Za-z0-9_-]{43}$/', $value)) {
            $r->addError('Invalid reset token');
        }
        return $r;
    }

    public static function issue(): self
    {
        return self::fromNative(bin2hex(random_bytes(16)) . '.' . rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '='));
    }

    public function selector(): string
    {
        return explode('.', (string) $this->value)[0];
    }

    public function verifierHash(): string
    {
        return hash('sha256', explode('.', (string) $this->value)[1]);
    }
}
