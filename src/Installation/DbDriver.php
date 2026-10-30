<?php
declare(strict_types=1);

namespace Bastion\Installation;

use dzentota\TypedValue\Typed;
use dzentota\TypedValue\TypedValue;
use dzentota\TypedValue\ValidationResult;

/** @implements Typed<string> */
final class DbDriver implements Typed
{
    /** @use TypedValue<string> */
    use TypedValue;

    public static function validate($value): ValidationResult
    {
        $r = new ValidationResult();
        if (!in_array($value, ['sqlite', 'mysql'], true)) {
            $r->addError('Database driver must be sqlite or mysql');
        }
        return $r;
    }
}
