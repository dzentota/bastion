<?php
declare(strict_types=1);

namespace Bastion\Extension\Api;

interface ContentReader
{
    /** @return list<PublishedEntry> */
    public function latest(int $limit): array;
}
