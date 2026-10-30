<?php
declare(strict_types=1);

namespace Bastion\Extensions\Application;

use Bastion\Extensions\Domain\Manifest;

final class Package
{
    /** @param array<string, string> $files путь => содержимое (уже проверены) */
    public function __construct(public readonly Manifest $manifest, public readonly array $files)
    {
    }

    /** @return array<string, string> только исполняемые файлы */
    public function phpFiles(): array
    {
        return array_filter($this->files, static fn (string $p) => str_ends_with($p, '.php'), ARRAY_FILTER_USE_KEY);
    }
}
