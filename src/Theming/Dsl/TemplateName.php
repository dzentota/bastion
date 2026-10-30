<?php
declare(strict_types=1);

namespace Bastion\Theming\Dsl;

use dzentota\TypedValue\Typed;
use dzentota\TypedValue\TypedValue;
use dzentota\TypedValue\ValidationResult;

/**
 * Имя шаблона темы: только [a-z0-9_-] сегменты через "/", без "..", без расширения.
 * Исключает path traversal при include (ADR-0013, abuser story template-code-exec).
 *
 * @implements Typed<string>
 */
final class TemplateName implements Typed
{
    /** @use TypedValue<string> */
    use TypedValue;

    public static function validate($value): ValidationResult
    {
        $result = new ValidationResult();
        if (!is_string($value) || !preg_match('~^[a-z0-9_-]+(/[a-z0-9_-]+)*$~', $value) || strlen($value) > 128) {
            $result->addError('Invalid template name');
        }
        return $result;
    }
}
