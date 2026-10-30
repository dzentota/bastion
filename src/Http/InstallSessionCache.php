<?php
declare(strict_types=1);

namespace Bastion\Http;

use Bastion\Installation\Paths;
use Psr\SimpleCache\CacheInterface;

/**
 * Минимальный файловый PSR-16 только для сессий установщика (до установки БД нет).
 * Ключи хешируются — имя файла не контролируется клиентом.
 */
final class InstallSessionCache implements CacheInterface
{
    public function __construct(private readonly Paths $paths)
    {
    }

    public function get(string $key, mixed $default = null): mixed
    {
        $f = $this->file($key);
        if (!is_file($f)) {
            return $default;
        }
        $data = json_decode((string) file_get_contents($f), true);
        if (!is_array($data) || $data['exp'] < time()) {
            @unlink($f);
            return $default;
        }
        return $data['v'];
    }

    public function set(string $key, mixed $value, null|int|\DateInterval $ttl = null): bool
    {
        $ttl = $ttl instanceof \DateInterval ? (new \DateTimeImmutable())->add($ttl)->getTimestamp() - time() : ($ttl ?? 3600);
        $dir = dirname($this->file($key));
        if (!is_dir($dir)) {
            mkdir($dir, 0700, true);
        }
        return file_put_contents($this->file($key), json_encode(['exp' => time() + $ttl, 'v' => $value]), LOCK_EX) !== false;
    }

    public function delete(string $key): bool
    {
        @unlink($this->file($key));
        return true;
    }

    public function clear(): bool
    {
        array_map('unlink', glob($this->paths->var('install-sessions/*')) ?: []);
        return true;
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        foreach ($keys as $k) {
            yield $k => $this->get($k, $default);
        }
    }

    public function setMultiple(iterable $values, null|int|\DateInterval $ttl = null): bool
    {
        foreach ($values as $k => $v) {
            $this->set($k, $v, $ttl);
        }
        return true;
    }

    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $k) {
            $this->delete($k);
        }
        return true;
    }

    public function has(string $key): bool
    {
        return $this->get($key, $this) !== $this;
    }

    private function file(string $key): string
    {
        return $this->paths->var('install-sessions/' . hash('sha256', $key));
    }
}
