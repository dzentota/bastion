<?php
declare(strict_types=1);

namespace Bastion\Comments\Domain;

use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};

/**
 * IP комментатора не хранится: только HMAC с секретом сайта. Этого достаточно, чтобы
 * считать лимиты и банить повторяющийся спам, но из дампа БД IP не восстановить
 * (перебор 2^32 IPv4 без ключа бесполезен).
 */
#[AssetId('bastion-app')]
#[AbuserStory('commenter-deanonymisation')]
#[Mitigation(cwe: 'CWE-359', description: 'No email collected; IP stored only as keyed HMAC-SHA256 (key outside the database)')]
final class CommenterFingerprint
{
    public function __construct(#[\SensitiveParameter] private readonly string $key)
    {
        if (strlen($key) < 32) {
            throw new \InvalidArgumentException('Fingerprint key must be at least 32 bytes');
        }
    }

    public function of(string $ip): string
    {
        return substr(hash_hmac('sha256', 'comment-ip:' . $ip, $this->key), 0, 32);
    }
}
