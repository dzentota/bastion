<?php
declare(strict_types=1);

namespace Bastion\Extensions\Domain;

use dzentota\TypedValue\Typed;
use dzentota\TypedValue\TypedValue;
use dzentota\TypedValue\ValidationResult;

/** @implements Typed<string> */
final class ExtensionVersion implements Typed
{
    /** @use TypedValue<string> */
    use TypedValue;

    public static function validate($value): ValidationResult
    {
        $r = new ValidationResult();
        if (!is_string($value) || !preg_match('/^(0|[1-9]\d{0,4})\.(0|[1-9]\d{0,4})\.(0|[1-9]\d{0,4})$/', $value)) {
            $r->addError('Version must be MAJOR.MINOR.PATCH');
        }
        return $r;
    }

    public function isNewerThan(self $other): bool
    {
        return version_compare((string) $this->value, (string) $other->value, '>');
    }
}
