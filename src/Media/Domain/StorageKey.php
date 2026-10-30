<?php
declare(strict_types=1);

namespace Bastion\Media\Domain;

use dzentota\TypedValue\Typed;
use dzentota\TypedValue\TypedValue;
use dzentota\TypedValue\ValidationResult;

/**
 * Ключ объекта в хранилище. Строится только из MediaId и MediaKind; грамматика
 * исключает "..", "/" в начале, нулевые байты и исполняемые расширения (abuser story media-path-traversal).
 * @implements Typed<string>
 */
final class StorageKey implements Typed
{
    /** @use TypedValue<string> */
    use TypedValue;

    public static function validate($value): ValidationResult
    {
        $r = new ValidationResult();
        if (!is_string($value) || !preg_match('~^media/[0-9a-f]{2}/[0-9a-f]{32}\.(jpg|png|webp|gif|pdf)$~', $value)) {
            $r->addError('Invalid storage key');
        }
        return $r;
    }

    public static function for(MediaId $id, MediaKind $kind): self
    {
        $hex = $id->toNative();
        return self::fromNative('media/' . substr($hex, 0, 2) . '/' . $hex . '.' . $kind->extension());
    }
}
