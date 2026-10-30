<?php
declare(strict_types=1);

namespace Bastion\IdentityAccess\Domain;

use DomainPrimitives\Common\Email;
use dzentota\TypedValue\Typed;
use dzentota\TypedValue\TypedValue;
use dzentota\TypedValue\ValidationResult;

/**
 * Email сотрудника. Валидация — dzentota/domain-primitives (Email отвергает CR/LF,
 * пробелы и прочее, что могло бы стать заголовком письма). Хранится в нижнем регистре.
 * @implements Typed<string>
 */
final class StaffEmail implements Typed
{
    /** @use TypedValue<string> */
    use TypedValue;

    public static function validate($value): ValidationResult
    {
        $r = new ValidationResult();
        if (!is_string($value) || $value !== strtolower($value) || !Email::tryParse($value)) {
            $r->addError('Invalid email address');
        }
        return $r;
    }

    public static function fromInput(string $raw): ?self
    {
        return self::tryParse(strtolower(trim($raw)), $email) ? $email : null;
    }
}
