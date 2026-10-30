<?php
declare(strict_types=1);

namespace Bastion\Shared\Domain;

use dzentota\TypedValue\ValidationResult;

/**
 * Общая проверка для текстовых примитивов: валидный UTF-8, без управляющих символов
 * (кроме разрешённых), длина в символах в пределах [min, max].
 */
final class BoundedText
{
    public static function check(mixed $value, int $min, int $max, bool $multiline): ValidationResult
    {
        $r = new ValidationResult();
        if (!is_string($value) || !mb_check_encoding($value, 'UTF-8')) {
            $r->addError('Must be a valid UTF-8 string');
            return $r;
        }
        $controls = $multiline ? '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\x{202A}-\x{202E}\x{2066}-\x{2069}]/u'
                               : '/[\x00-\x1F\x7F\x{202A}-\x{202E}\x{2066}-\x{2069}]/u';
        if (preg_match($controls, $value)) {
            $r->addError('Contains forbidden control characters');
        }
        $len = mb_strlen($value);
        if ($len < $min || $len > $max) {
            $r->addError("Length must be between {$min} and {$max}");
        }
        return $r;
    }
}
