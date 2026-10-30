<?php
declare(strict_types=1);

namespace Bastion\Tests\Theming\Dsl;

use Bastion\Theming\Dsl\{TemplateName, TemplateNotFound, TemplateSource};

final class InMemorySource implements TemplateSource
{
    /** @param array<string, string> $templates */
    public function __construct(private array $templates)
    {
    }

    public function load(TemplateName $name): string
    {
        return $this->templates[$name->toNative()] ?? throw new TemplateNotFound($name->toNative());
    }
}
