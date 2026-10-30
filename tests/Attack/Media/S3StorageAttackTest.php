<?php
declare(strict_types=1);

namespace Bastion\Tests\Attack\Media;

use Bastion\Media\Domain\{MediaId, MediaKind, StorageKey};
use Bastion\Media\Infrastructure\{S3Config, S3MediaStorage};
use Bastion\Tests\Support\FrozenClock;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\{RequestInterface, ResponseInterface};

/** Abuser stories: storage-endpoint-ssrf, storage-credential-leak. */
final class S3StorageAttackTest extends TestCase
{
    private const SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

    public static function forbiddenEndpoints(): iterable
    {
        yield 'plain http' => ['http://s3.example.com'];
        yield 'metadata service' => ['https://169.254.169.254'];
        yield 'loopback' => ['https://127.0.0.1'];
        yield 'private' => ['https://10.0.0.5:9000'];
        yield 'decimal ip' => ['https://2130706433'];
        yield 'hex ip' => ['https://0x7f000001'];
        yield 'path injection' => ['https://s3.example.com/../admin'];
        yield 'credentials in url' => ['https://user:pass@s3.example.com'];
    }

    #[DataProvider('forbiddenEndpoints')]
    public function testDangerousEndpointsAreRejectedAtConfigTime(string $endpoint): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new S3Config($endpoint, 'auto', 'media', 'AKIAIOSFODNN7EXAMPLE', self::SECRET);
    }

    public function testRequestIsSignedAndSecretNeverLeaves(): void
    {
        $client = new class implements ClientInterface {
            /** @var list<RequestInterface> */
            public array $sent = [];
            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                $this->sent[] = $request;
                return new Response(200);
            }
        };
        $f = new Psr17Factory();
        $config = new S3Config('https://account.r2.cloudflarestorage.com', 'auto', 'media', 'AKIAIOSFODNN7EXAMPLE', self::SECRET);
        $storage = new S3MediaStorage($config, $client, $f, $f, new FrozenClock());
        $key = StorageKey::for(MediaId::fromNative(str_repeat('ab', 16)), MediaKind::Png);
        $storage->put($key, 'bytes', MediaKind::Png);

        $req = $client->sent[0];
        self::assertSame('https://account.r2.cloudflarestorage.com/media/media/ab/' . str_repeat('ab', 16) . '.png', (string) $req->getUri());
        self::assertMatchesRegularExpression(
            '~^AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20261030/auto/s3/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, Signature=[0-9a-f]{64}$~',
            $req->getHeaderLine('Authorization'),
        );
        self::assertSame(hash('sha256', 'bytes'), $req->getHeaderLine('x-amz-content-sha256'));
        $wire = $req->getMethod() . (string) $req->getUri() . json_encode($req->getHeaders()) . $req->getBody();
        self::assertStringNotContainsString(self::SECRET, $wire);
        self::assertStringNotContainsString(self::SECRET, print_r($config, true));
    }
}
