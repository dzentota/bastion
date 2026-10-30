<?php
declare(strict_types=1);

namespace Bastion\Theming\Dsl;

use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};
/**
 * Кэш AST, подписанный HMAC-SHA256 (abuser story template-cache-tamper).
 * Хранится JSON-данные, не PHP: даже при подмене кэша исполнить код нельзя,
 * а подпись не даёт подменить разметку.
 */
#[AbuserStory('template-cache-tamper')]
#[Mitigation(cwe: 'CWE-494', description: 'Cache holds data (JSON AST) authenticated with HMAC-SHA256; tampering raises CacheTampered')]
#[AssetId('bastion-app')]
final class SignedAstCache
{
    public function __construct(private readonly string $directory, #[\SensitiveParameter] private readonly string $key)
    {
        if (strlen($key) < 32) {
            throw new \InvalidArgumentException('Cache key must be at least 32 bytes');
        }
    }

    /** @return list<array<string, mixed>>|null */
    public function get(TemplateName $name, string $source): ?array
    {
        $file = $this->path($name);
        if (!is_file($file)) {
            return null;
        }
        $raw = (string) file_get_contents($file);
        $mac = substr($raw, 0, 64);
        $payload = substr($raw, 64);
        if (!hash_equals(hash_hmac('sha256', $payload, $this->key), $mac)) {
            throw new CacheTampered($name->toNative());
        }
        $data = json_decode($payload, true, 512, JSON_THROW_ON_ERROR);
        // исходник изменился — кэш устарел (это не атака)
        return $data['src'] === hash('sha256', $source) ? $data['ast'] : null;
    }

    /** @param list<array<string, mixed>> $ast */
    public function put(TemplateName $name, string $source, array $ast): void
    {
        $payload = json_encode(['src' => hash('sha256', $source), 'ast' => $ast], JSON_THROW_ON_ERROR);
        $file = $this->path($name);
        $tmp = $file . '.' . bin2hex(random_bytes(8));
        file_put_contents($tmp, hash_hmac('sha256', $payload, $this->key) . $payload, LOCK_EX);
        rename($tmp, $file);
    }

    private function path(TemplateName $name): string
    {
        return $this->directory . '/' . hash('sha256', $name->toNative()) . '.ast';
    }
}
