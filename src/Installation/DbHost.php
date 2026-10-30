<?php
declare(strict_types=1);

namespace Bastion\Installation;

use dzentota\TypedValue\Typed;
use dzentota\TypedValue\TypedValue;
use dzentota\TypedValue\ValidationResult;

final class DbHost implements Typed
{
    use TypedValue;

    public static function validate($value): ValidationResult
    {
        $r = new ValidationResult();
        if (!is_string($value) || !preg_match('/^[A-Za-z0-9.-]{1,253}$/', $value)) {
            $r->addError('Invalid database host');
        }
        return $r;
    }
}
