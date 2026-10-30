<?php
declare(strict_types=1);

namespace Bastion\Media\Domain;

/** Порт хранилища медиа (ADR-0011). */
interface MediaStorage
{
    public function put(StorageKey $key, string $bytes, MediaKind $kind): void;

    /** @throws MediaNotFound */
    public function get(StorageKey $key): string;

    public function delete(StorageKey $key): void;

    /** true для локального хранилища — Degraded Mode, показывается в админке. */
    public function isDegraded(): bool;
}
