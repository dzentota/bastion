<?php
declare(strict_types=1);

namespace Bastion\Comments\Domain;

use dzentota\TypedValue\Typed;
use dzentota\TypedValue\TypedValue;
use dzentota\TypedValue\ValidationResult;

/** @implements Typed<string> */
final class CommentId implements Typed
{
    /** @use TypedValue<string> */
    use TypedValue;

    public static function validate($value): ValidationResult
    {
        $r = new ValidationResult();
        if (!is_string($value) || !preg_match('/^[0-9a-f]{32}$/', $value)) {
            $r->addError('Invalid comment id');
        }
        return $r;
    }

    public static function generate(): self
    {
        return self::fromNative(bin2hex(random_bytes(16)));
    }
}
