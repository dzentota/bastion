<?php
declare(strict_types=1);

namespace Bastion\Theming\Dsl;

final class DirectoryTemplateSource implements TemplateSource
{
    public function __construct(private readonly string $directory)
    {
    }

    public function load(TemplateName $name): string
    {
        // TemplateName уже исключает "..", абсолютные пути и нулевые байты.
        $path = $this->directory . '/' . $name->toNative() . '.tpl';
        if (!is_file($path)) {
            throw new TemplateNotFound($name->toNative());
        }
        $source = file_get_contents($path);
        if ($source === false) {
            throw new TemplateNotFound($name->toNative());
        }
        return $source;
    }
}
