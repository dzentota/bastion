<?php
declare(strict_types=1);

namespace Bastion\Theming\Dsl;

/** Откуда брать исходники шаблонов активной темы. */
interface TemplateSource
{
    /** @throws TemplateNotFound */
    public function load(TemplateName $name): string;
}
