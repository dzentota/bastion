<?php
declare(strict_types=1);

namespace Bastion\Comments\Domain;

use Bastion\Shared\Domain\BoundedText;
use dzentota\TypedValue\Typed;
use dzentota\TypedValue\TypedValue;
use dzentota\TypedValue\ValidationResult;

/**
 * Простой текст. Разметка не интерпретируется никогда — только экранируется при выводе.
 * @implements Typed<string>
 */
final class CommentBody implements Typed
{
    /** @use TypedValue<string> */
    use TypedValue;

    public static function validate($value): ValidationResult
    {
        return BoundedText::check($value, 1, 5000, true);
    }

    public function linkCount(): int
    {
        return (int) preg_match_all('~(https?://|www\.)~i', $this->toNative());
    }

    /** @return list<string> */
    public function lines(): array
    {
        return explode("\n", str_replace("\r\n", "\n", $this->toNative()));
    }
}
