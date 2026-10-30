<?php
declare(strict_types=1);

namespace Bastion\Extension\Api;

/** Только скаляры: расширение не получает доменные объекты и сервисы ядра. */
final class PublishedEntry
{
    public function __construct(
        public readonly string $title,
        public readonly string $url,
        public readonly string $date,
    ) {
    }
}
