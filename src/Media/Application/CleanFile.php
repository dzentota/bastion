<?php
declare(strict_types=1);

namespace Bastion\Media\Application;

use Bastion\Media\Domain\MediaKind;

final class CleanFile
{
    public function __construct(
        public readonly MediaKind $kind,
        public readonly string $bytes,
        public readonly ?int $width,
        public readonly ?int $height,
    ) {
    }
}
