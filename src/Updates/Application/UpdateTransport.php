<?php
declare(strict_types=1);

namespace Bastion\Updates\Application;

interface UpdateTransport
{
    /** @return array{status: int, body: string, signature: string} тело обрезается/отвергается свыше $maxBytes */
    public function get(string $url, int $maxBytes): array;
}
