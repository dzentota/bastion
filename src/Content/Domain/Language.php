<?php
declare(strict_types=1);

namespace Bastion\Content\Domain;

use dzentota\TypedValue\Typed;
use dzentota\TypedValue\TypedValue;
use dzentota\TypedValue\ValidationResult;

/**
 * Код языка ISO 639-1 (en, ru). Допустим ли он на сайте — решает SiteLanguages.
 * @implements Typed<string>
 */
final class Language implements Typed
{
    /** @use TypedValue<string> */
    use TypedValue;

    public static function validate($value): ValidationResult
    {
        $r = new ValidationResult();
        if (!is_string($value) || !preg_match('/^[a-z]{2}$/', $value)) {
            $r->addError('Language must be a two-letter ISO 639-1 code');
        }
        return $r;
    }
}
