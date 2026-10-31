<?php
declare(strict_types=1);

namespace Bastion\Taxonomy\Domain;

use dzentota\TypedValue\Typed;
use dzentota\TypedValue\TypedValue;
use dzentota\TypedValue\ValidationResult;

/**
 * Номер страницы листинга: 1..MAX. Глубокие OFFSET не выполняются вовсе.
 *
 * @implements Typed<string>
 */
final class PageNumber implements Typed
{
    /** @use TypedValue<string> */
    use TypedValue;

    public const MAX = 50;

    public static function validate($value): ValidationResult
    {
        $r = new ValidationResult();
        if (!is_string($value) || !preg_match('/^[1-9][0-9]{0,1}$/', $value) || (int) $value > self::MAX) {
            $r->addError('Page must be an integer 1..' . self::MAX);
        }
        return $r;
    }

    public function toInt(): int
    {
        return (int) $this->toNative();
    }
}
