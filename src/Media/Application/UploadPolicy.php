<?php
declare(strict_types=1);

namespace Bastion\Media\Application;

final class UploadPolicy
{
    public function __construct(
        public readonly int $maxBytes = 10 * 1024 * 1024,
        public readonly int $maxPixels = 40_000_000,
        public readonly int $maxSide = 12_000,
        public readonly int $maxUploadsPerDay = 200,
        public readonly int $maxBytesPerDay = 500 * 1024 * 1024,
    ) {
    }
}
