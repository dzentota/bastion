<?php
declare(strict_types=1);

namespace Bastion\Comments\Application;

final class CommentPolicy
{
    public function __construct(
        public readonly int $maxPerSourcePerWindow = 5,
        public readonly int $windowSeconds = 600,
        public readonly int $maxPendingQueue = 1000,
        public readonly int $spamLinkThreshold = 3,
    ) {
    }
}
