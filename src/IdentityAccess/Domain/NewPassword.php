<?php
declare(strict_types=1);

namespace Bastion\IdentityAccess\Domain;

use dzentota\TypedValue\Security\ProhibitedFromLogs;
use dzentota\TypedValue\Security\SecurityStrategy;
use dzentota\TypedValue\Typed;
use dzentota\TypedValue\TypedValue;
use dzentota\TypedValue\ValidationResult;
use ZxcvbnPhp\Zxcvbn;

/**
 * Новый пароль, прошедший политику: ≥12 символов, ≤1024 байт, zxcvbn ≥ 3,
 * не содержит имени пользователя.
 *
 * @implements Typed<string>
 */
final class NewPassword implements Typed, ProhibitedFromLogs
{
    /** @use TypedValue<string> */
    use TypedValue;

    public static function validate($value): ValidationResult
    {
        $r = new ValidationResult();
        if (!is_string($value) || !mb_check_encoding($value, 'UTF-8') || mb_strlen($value) < 12 || strlen($value) > 1024) {
            $r->addError('Password must be 12+ characters');
            return $r;
        }
        if ((new Zxcvbn())->passwordStrength($value)['score'] < 3) {
            $r->addError('Password is too easy to guess');
        }
        return $r;
    }

    public static function forUser(string $password, Username $username, ?ValidationResult &$result = null): ?self
    {
        $result = self::validate($password);
        if ($result->success() && str_contains(mb_strtolower($password), $username->toNative())) {
            $result->addError('Password must not contain the username');
        }
        return $result->success() ? self::fromNative($password) : null;
    }

    public static function getLoggingSecurityStrategy(): SecurityStrategy
    {
        return SecurityStrategy::PROHIBIT;
    }

    public function getSafeLoggableRepresentation(): string
    {
        return '[prohibited]';
    }

    public function __debugInfo(): array
    {
        return ['value' => '***'];
    }
}
