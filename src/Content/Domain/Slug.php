<?php
declare(strict_types=1);

namespace Bastion\Content\Domain;

use dzentota\TypedValue\Typed;
use dzentota\TypedValue\TypedValue;
use dzentota\TypedValue\ValidationResult;

/** @implements Typed<string> */
final class Slug implements Typed
{
    /** @use TypedValue<string> */
    use TypedValue;

    public static function validate($value): ValidationResult
    {
        $r = new ValidationResult();
        if (!is_string($value) || !preg_match('/^[a-z0-9]+(?:-[a-z0-9]+)*$/', $value) || strlen($value) > 96) {
            $r->addError('Slug must be lowercase latin letters, digits and single dashes, max 96 chars');
        }
        return $r;
    }
}
