<?php
declare(strict_types=1);

namespace Bastion\Content\Domain\Block;

use Bastion\Shared\Domain\BoundedText;
use dzentota\TypedValue\Typed;
use dzentota\TypedValue\TypedValue;
use dzentota\TypedValue\ValidationResult;

/** Простой текст внутри блока. Разметка не интерпретируется — только экранируется при выводе. */
final class BlockText implements Typed
{
    use TypedValue;

    public static function validate($value): ValidationResult
    {
        return BoundedText::check($value, 1, 20000, true);
    }
}
