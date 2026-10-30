<?php
declare(strict_types=1);

namespace Bastion\Media\Domain;

use Bastion\Shared\Domain\BoundedText;
use dzentota\TypedValue\Typed;
use dzentota\TypedValue\TypedValue;
use dzentota\TypedValue\ValidationResult;

/**
 * Имя файла от клиента — только для показа в админке. На диске и в URL не используется.
 * @implements Typed<string>
 */
final class DisplayName implements Typed
{
    /** @use TypedValue<string> */
    use TypedValue;

    public static function validate($value): ValidationResult
    {
        return BoundedText::check($value, 1, 120, false);
    }

    public static function fromClient(?string $clientName): self
    {
        $name = basename(str_replace('\\', '/', (string) $clientName));
        $name = mb_substr(trim((string) preg_replace('/[\x00-\x1F\x7F\x{202A}-\x{202E}\x{2066}-\x{2069}]/u', '', $name)), 0, 120);
        return self::tryParse($name, $display) ? $display : self::fromNative('file');
    }
}
