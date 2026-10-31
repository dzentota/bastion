<?php
declare(strict_types=1);

namespace Bastion\Tests\Support;

use Bastion\Updates\Application\{ChronicleFeed, UpdateTransport};

/** Chronicle + реестр релизов в памяти: подписывает ответы ключом сервера, ведёт хэш-цепочку. */
final class FakeChronicle implements UpdateTransport
{
    public readonly string $serverPublic;
    private string $serverSecret;
    /** @var list<array{contents: string, prev: string, hash: string}> */
    public array $entries = [];
    /** @var array<string, string> url => body реестра */
    public array $files = [];

    public function __construct()
    {
        $pair = sodium_crypto_sign_keypair();
        $this->serverSecret = sodium_crypto_sign_secretkey($pair);
        $this->serverPublic = base64_encode(sodium_crypto_sign_publickey($pair));
    }

    public function publish(string $envelope): void
    {
        $prev = $this->entries === [] ? '' : $this->entries[array_key_last($this->entries)]['hash'];
        $this->entries[] = ['contents' => $envelope, 'prev' => $prev, 'hash' => ChronicleFeed::hash($prev, $envelope)];
    }

    public function release(string $name, string $version, string $zip, string $sig): void
    {
        $base = 'https://registry.test/' . $name;
        $this->files[$base . '/latest.json'] = json_encode(['version' => $version], JSON_THROW_ON_ERROR);
        $this->files[$base . "/{$version}.zip"] = $zip;
        $this->files[$base . "/{$version}.zip.sig"] = $sig;
    }

    /** @param list<array{contents: string, prev: string, hash: string}>|null $entries */
    public function body(?array $entries = null): string
    {
        return json_encode(['version' => '1.2.x', 'status' => 'OK', 'results' => $entries ?? $this->entries], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }

    public function sign(string $body): string
    {
        return base64_encode(sodium_crypto_sign_detached($body, $this->serverSecret));
    }

    public function get(string $url, int $maxBytes): array
    {
        if (preg_match('~^https://chronicle\.test/chronicle/(export|since/(.+))$~', $url, $m)) {
            $since = isset($m[2]) ? rawurldecode($m[2]) : null;
            $start = 0;
            if ($since !== null) {
                $start = (int) array_search($since, array_column($this->entries, 'hash'), true) + 1;
            }
            $body = $this->body(array_slice($this->entries, $start));
            return ['status' => 200, 'body' => $body, 'signature' => $this->sign($body)];
        }
        return isset($this->files[$url]) ? ['status' => 200, 'body' => $this->files[$url], 'signature' => ''] : ['status' => 404, 'body' => '', 'signature' => ''];
    }
}
