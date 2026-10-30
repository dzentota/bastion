<?php
declare(strict_types=1);

namespace Bastion\Content\Domain;

use Bastion\Shared\Domain\BoundedText;
use dzentota\TypedValue\Typed;
use dzentota\TypedValue\TypedValue;
use dzentota\TypedValue\ValidationResult;

/** @implements Typed<string> */
final class Title implements Typed
{
    /** @use TypedValue<string> */
    use TypedValue;

    public static function validate($value): ValidationResult
    {
        return BoundedText::check($value, 1, 200, false);
    }
}
