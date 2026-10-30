<?php
declare(strict_types=1);

namespace Bastion\Theming\Dsl;

final class TemplateSyntaxError extends \RuntimeException
{
    public static function at(string $template, int $line, string $message): self
    {
        return new self(sprintf('%s:%d: %s', $template, $line, $message));
    }
}
