<?php
declare(strict_types=1);

namespace Bastion\Extensions\Domain;

/** Запись реестра. Целостность всех полей защищена HMAC (см. ExtensionRegistry). */
final class InstalledExtension
{
    /**
     * @param array<string, string> $fileHashes путь => sha256
     * @param list<ExtCapability> $granted
     */
    public function __construct(
        public readonly Manifest $manifest,
        public readonly array $fileHashes,
        public readonly array $granted,
        public readonly bool $enabled,
    ) {
    }
}
