<?php
declare(strict_types=1);

namespace Bastion\Content\Domain;

use dzentota\TypedValue\Typed;
use dzentota\TypedValue\TypedValue;
use dzentota\TypedValue\ValidationResult;

/**
 * Позиция страницы в меню сайта: 1..99, меньше — левее.
 * @implements Typed<string>
 */
final class MenuPosition implements Typed
{
    /** @use TypedValue<string> */
    use TypedValue;

    public static function validate($value): ValidationResult
    {
        $r = new ValidationResult();
        if (!is_string($value) || !preg_match('/^[1-9][0-9]?$/', $value)) {
            $r->addError('Menu position must be 1..99');
        }
        return $r;
    }

    public function toInt(): int
    {
        return (int) $this->toNative();
    }
}
