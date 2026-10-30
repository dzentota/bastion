<?php
declare(strict_types=1);

namespace Bastion\Media\Infrastructure;

use Bastion\Media\Domain\{MediaKind, MediaNotFound, MediaStorage, StorageKey};

/**
 * Degraded Mode (ADR-0011): файлы в var/media — вне webroot, с правами 0600, под системными
 * ключами без исполняемых расширений. Раздаются только через MediaController.
 */
final class LocalMediaStorage implements MediaStorage
{
    public function __construct(private readonly string $root)
    {
    }

    public function put(StorageKey $key, string $bytes, MediaKind $kind): void
    {
        $file = $this->path($key);
        $dir = dirname($file);
        if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new \RuntimeException('Cannot create media directory');
        }
        $tmp = $file . '.' . bin2hex(random_bytes(6)) . '.tmp';
        if (file_put_contents($tmp, $bytes, LOCK_EX) === false) {
            throw new \RuntimeException('Cannot write media file');
        }
        chmod($tmp, 0600);
        rename($tmp, $file);
    }

    public function get(StorageKey $key): string
    {
        $file = $this->path($key);
        $bytes = is_file($file) ? file_get_contents($file) : false;
        return $bytes === false ? throw new MediaNotFound($key->toNative()) : $bytes;
    }

    public function delete(StorageKey $key): void
    {
        @unlink($this->path($key));
    }

    public function isDegraded(): bool
    {
        return true;
    }

    private function path(StorageKey $key): string
    {
        // StorageKey исключает "..", абсолютные пути и нулевые байты.
        return $this->root . '/' . $key->toNative();
    }
}
