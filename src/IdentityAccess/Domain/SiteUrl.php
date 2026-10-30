<?php
declare(strict_types=1);

namespace Bastion\IdentityAccess\Domain;

use dzentota\TypedValue\Typed;
use dzentota\TypedValue\TypedValue;
use dzentota\TypedValue\ValidationResult;

/**
 * Канонический адрес сайта из конфигурации. Ссылки в письмах строятся только из него,
 * никогда из заголовка Host запроса (abuser story reset-host-poisoning).
 * @implements Typed<string>
 */
final class SiteUrl implements Typed
{
    /** @use TypedValue<string> */
    use TypedValue;

    public static function validate($value): ValidationResult
    {
        $r = new ValidationResult();
        if (!is_string($value) || !preg_match('~^https?://[a-z0-9.-]+(:\d{1,5})?$~', $value)) {
            $r->addError('Site URL must be scheme://host[:port] without a path');
        }
        return $r;
    }

    public function link(string $path): string
    {
        return $this->value . '/' . ltrim($path, '/');
    }
}
