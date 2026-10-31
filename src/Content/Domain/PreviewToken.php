<?php
declare(strict_types=1);

namespace Bastion\Content\Domain;

use dzentota\TypedValue\Typed;
use dzentota\TypedValue\TypedValue;
use dzentota\TypedValue\ValidationResult;

/**
 * Токен предпросмотра в URL: base64url(полезная нагрузка) + base64url(HMAC) — подпись всегда
 * последние 43 символа, без разделителя (redirect() допускает только [A-Za-z0-9/_-]). Здесь — только форма;
 * подпись, срок и привязку к пользователю проверяет PreviewTokens.
 * @implements Typed<string>
 */
final class PreviewToken implements Typed
{
    /** @use TypedValue<string> */
    use TypedValue;

    public static function validate($value): ValidationResult
    {
        $r = new ValidationResult();
        if (!is_string($value) || strlen($value) > 300 || !preg_match('/^[A-Za-z0-9_-]{44,300}$/', $value)) {
            $r->addError('Malformed preview token');
        }
        return $r;
    }
}
