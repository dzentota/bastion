<?php
declare(strict_types=1);

namespace Bastion\Content\Domain;

use dzentota\TypedValue\Typed;
use dzentota\TypedValue\TypedValue;
use dzentota\TypedValue\ValidationResult;

/**
 * Номер ревизии в URL: 1…999999, без ведущих нулей.
 * @implements Typed<string>
 */
final class RevisionNumber implements Typed
{
    /** @use TypedValue<string> */
    use TypedValue;

    public static function validate($value): ValidationResult
    {
        $r = new ValidationResult();
        if (!is_string($value) || !preg_match('/^[1-9][0-9]{0,5}$/', $value)) {
            $r->addError('Revision number must be 1–999999');
        }
        return $r;
    }

    public function toInt(): int
    {
        return (int) $this->toNative();
    }
}
