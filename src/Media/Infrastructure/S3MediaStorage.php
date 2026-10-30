<?php
declare(strict_types=1);

namespace Bastion\Media\Infrastructure;

use Bastion\Media\Domain\{MediaKind, MediaNotFound, MediaStorage, StorageKey};
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};
use Psr\Clock\ClockInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\{RequestFactoryInterface, StreamFactoryInterface};

/**
 * S3-совместимое хранилище, path-style, подпись AWS SigV4.
 * HTTP — только через dzentota/http-client (защита от SSRF и DNS rebinding).
 */
#[AssetId('bastion-app')]
#[AbuserStory('storage-endpoint-ssrf')]
#[Mitigation(cwe: 'CWE-918', description: 'Endpoint must be https://host; requests go through dzentota/http-client which resolves DNS once and blocks private, loopback and link-local addresses')]
final class S3MediaStorage implements MediaStorage
{
    public function __construct(
        private readonly S3Config $config,
        private readonly ClientInterface $http,
        private readonly RequestFactoryInterface $requests,
        private readonly StreamFactoryInterface $streams,
        private readonly ClockInterface $clock,
    ) {
    }

    public function put(StorageKey $key, string $bytes, MediaKind $kind): void
    {
        $res = $this->send('PUT', $key, $bytes, ['content-type' => $kind->mime()]);
        if ($res->getStatusCode() !== 200) {
            throw new \RuntimeException('S3 PUT failed with HTTP ' . $res->getStatusCode());
        }
    }

    public function get(StorageKey $key): string
    {
        $res = $this->send('GET', $key, '');
        return match ($res->getStatusCode()) {
            200 => (string) $res->getBody(),
            403, 404 => throw new MediaNotFound($key->toNative()),
            default => throw new \RuntimeException('S3 GET failed with HTTP ' . $res->getStatusCode()),
        };
    }

    public function delete(StorageKey $key): void
    {
        $res = $this->send('DELETE', $key, '');
        if (!in_array($res->getStatusCode(), [200, 204, 404], true)) {
            throw new \RuntimeException('S3 DELETE failed with HTTP ' . $res->getStatusCode());
        }
    }

    public function isDegraded(): bool
    {
        return false;
    }

    /** @param array<string, string> $extra */
    private function send(string $method, StorageKey $key, string $body, array $extra = []): \Psr\Http\Message\ResponseInterface
    {
        $host = (string) parse_url($this->config->endpoint, PHP_URL_HOST);
        $port = parse_url($this->config->endpoint, PHP_URL_PORT);
        $hostHeader = $host . ($port ? ':' . $port : '');
        $path = '/' . rawurlencode($this->config->bucket) . '/' . implode('/', array_map('rawurlencode', explode('/', $key->toNative())));
        $now = $this->clock->now()->setTimezone(new \DateTimeZone('UTC'));
        $amzDate = $now->format('Ymd\THis\Z');
        $date = $now->format('Ymd');
        $payloadHash = hash('sha256', $body);

        $headers = ['host' => $hostHeader, 'x-amz-content-sha256' => $payloadHash, 'x-amz-date' => $amzDate] + $extra;
        ksort($headers);
        $canonicalHeaders = '';
        foreach ($headers as $k => $v) {
            $canonicalHeaders .= $k . ':' . trim($v) . "\n";
        }
        $signedHeaders = implode(';', array_keys($headers));
        $canonicalRequest = implode("\n", [$method, $path, '', $canonicalHeaders, $signedHeaders, $payloadHash]);
        $scope = "{$date}/{$this->config->region}/s3/aws4_request";
        $stringToSign = implode("\n", ['AWS4-HMAC-SHA256', $amzDate, $scope, hash('sha256', $canonicalRequest)]);

        $k = hash_hmac('sha256', $date, 'AWS4' . $this->config->secretKey(), true);
        $k = hash_hmac('sha256', $this->config->region, $k, true);
        $k = hash_hmac('sha256', 's3', $k, true);
        $k = hash_hmac('sha256', 'aws4_request', $k, true);
        $signature = hash_hmac('sha256', $stringToSign, $k);

        $request = $this->requests->createRequest($method, $this->config->endpoint . $path)
            ->withHeader('Authorization', "AWS4-HMAC-SHA256 Credential={$this->config->accessKey}/{$scope}, SignedHeaders={$signedHeaders}, Signature={$signature}");
        foreach ($headers as $name => $value) {
            $request = $request->withHeader($name, $value);
        }
        if ($body !== '') {
            $request = $request->withBody($this->streams->createStream($body));
        }
        return $this->http->sendRequest($request);
    }
}
