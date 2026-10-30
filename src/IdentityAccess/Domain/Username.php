<?php
declare(strict_types=1);

namespace Bastion\IdentityAccess\Domain;

use dzentota\TypedValue\Typed;
use dzentota\TypedValue\TypedValue;
use dzentota\TypedValue\ValidationResult;

/** @implements Typed<string> */
final class Username implements Typed
{
    /** @use TypedValue<string> */
    use TypedValue;

    public static function validate($value): ValidationResult
    {
        $r = new ValidationResult();
        if (!is_string($value) || !preg_match('/^[a-z0-9][a-z0-9._-]{2,31}$/', $value)) {
            $r->addError('Username: 3-32 chars, lowercase latin letters, digits, . _ -');
        }
        return $r;
    }
}
