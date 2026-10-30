<?php
declare(strict_types=1);

namespace Bastion\Comments\Domain;

use Bastion\Shared\Domain\BoundedText;
use dzentota\TypedValue\Typed;
use dzentota\TypedValue\TypedValue;
use dzentota\TypedValue\ValidationResult;

/**
 * Отображаемое имя комментатора: одна строка, без управляющих и bidi-символов
 * (BoundedText), без невидимых символов нулевой ширины.
 * @implements Typed<string>
 */
final class CommentAuthor implements Typed
{
    /** @use TypedValue<string> */
    use TypedValue;

    public static function validate($value): ValidationResult
    {
        $r = BoundedText::check($value, 1, 60, false);
        if ($r->success() && is_string($value) && preg_match('/[\x{200B}-\x{200F}\x{2060}-\x{2064}\x{FEFF}\x{00AD}]/u', $value)) {
            $r->addError('Name contains invisible characters');
        }
        if ($r->success() && is_string($value) && trim($value) !== $value) {
            $r->addError('Name must not start or end with spaces');
        }
        return $r;
    }

    /** Ключ для сравнения с зарезервированными именами: регистр, совместимые формы, пробелы. */
    public function comparisonKey(): string
    {
        $v = $this->value;
        if (!is_string($v)) {
            return '';
        }
        if (class_exists(\Normalizer::class)) {
            $normalized = \Normalizer::normalize($v, \Normalizer::FORM_KC);
            $v = is_string($normalized) ? $normalized : $v;
        }
        return (string) preg_replace('/[\s._-]+/u', '', mb_strtolower($v));
    }
}
