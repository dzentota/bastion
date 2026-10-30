<?php
declare(strict_types=1);

namespace Bastion\Media\Infrastructure;

use dzentota\TypedValue\Security\{ProhibitedFromLogs, SecurityStrategy};
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};

/** Настройки S3-совместимого хранилища (AWS S3, Cloudflare R2, Backblaze B2, MinIO…). */
#[AssetId('bastion-app')]
#[AbuserStory('storage-credential-leak')]
#[Mitigation(cwe: 'CWE-522', description: 'Secret kept only in var/config.json (0600, outside webroot, denied by .htaccess); ProhibitedFromLogs, redacted in debug output, never rendered back in the admin UI')]
final class S3Config implements ProhibitedFromLogs
{
    public function __construct(
        public readonly string $endpoint,
        public readonly string $region,
        public readonly string $bucket,
        public readonly string $accessKey,
        #[\SensitiveParameter] private readonly string $secretKey,
    ) {
        if (!preg_match('~^https://[A-Za-z0-9.-]+(:\d{1,5})?$~', $endpoint)) {
            throw new \InvalidArgumentException('S3 endpoint must be https://host[:port] without a path');
        }
        // Defence in depth: IP-литералы проверяем сами (http-client проверяет только результат DNS).
        $host = (string) parse_url($endpoint, PHP_URL_HOST);
        if (preg_match('/^[0-9.]+$|^0x/i', $host)
            && filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            throw new \InvalidArgumentException('S3 endpoint must not be a private, reserved or non-canonical IP address');
        }
        if (!preg_match('/^[a-z0-9-]{1,32}$/', $region)) {
            throw new \InvalidArgumentException('Invalid S3 region');
        }
        if (!preg_match('/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/', $bucket)) {
            throw new \InvalidArgumentException('Invalid S3 bucket name');
        }
        if (!preg_match('/^[A-Za-z0-9]{8,128}$/', $accessKey) || strlen($secretKey) < 16 || strlen($secretKey) > 256) {
            throw new \InvalidArgumentException('Invalid S3 credentials');
        }
    }

    public function secretKey(): string
    {
        return $this->secretKey;
    }

    public static function getLoggingSecurityStrategy(): SecurityStrategy
    {
        return SecurityStrategy::PROHIBIT;
    }

    public function getSafeLoggableRepresentation(): string
    {
        return '[s3-config]';
    }

    /** @return array<string, string> */
    public function __debugInfo(): array
    {
        return ['endpoint' => $this->endpoint, 'bucket' => $this->bucket, 'secretKey' => '***'];
    }
}
