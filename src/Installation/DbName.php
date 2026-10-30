<?php
declare(strict_types=1);

namespace Bastion\Installation;

use dzentota\TypedValue\Typed;
use dzentota\TypedValue\TypedValue;
use dzentota\TypedValue\ValidationResult;

/** Имя БД или пользователя MySQL. *
 * @implements Typed<string>
 */
final class DbName implements Typed
{
    /** @use TypedValue<string> */
    use TypedValue;

    public static function validate($value): ValidationResult
    {
        $r = new ValidationResult();
        if (!is_string($value) || !preg_match('/^[A-Za-z0-9_]{1,64}$/', $value)) {
            $r->addError('Invalid database identifier');
        }
        return $r;
    }
}
