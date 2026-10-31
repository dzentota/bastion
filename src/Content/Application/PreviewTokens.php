<?php
declare(strict_types=1);

namespace Bastion\Content\Application;

use Bastion\Content\Domain\{EntryId, PreviewToken};
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};
use Psr\Clock\ClockInterface;

/** Выдача и проверка токенов предпросмотра ревизии. */
#[AssetId('bastion-app')]
#[AbuserStory('preview-token-abuse')]
#[Mitigation(cwe: 'CWE-345', description: 'Preview tokens are HMAC-signed with a derived key, compared in constant time')]
#[Mitigation(cwe: 'CWE-613', description: 'Tokens expire after 15 minutes')]
#[Mitigation(cwe: 'CWE-639', description: 'A token is bound to the account that requested it and is accepted only inside that account\'s staff session')]
final class PreviewTokens
{
    public const TTL = 900;

    public function __construct(private readonly string $key, private readonly ClockInterface $clock)
    {
    }

    public function issue(EntryId $revision, string $accountId): PreviewToken
    {
        $payload = self::b64(json_encode([$revision->toNative(), $accountId, $this->clock->now()->getTimestamp() + self::TTL], JSON_THROW_ON_ERROR));
        return PreviewToken::fromNative($payload . self::b64(hash_hmac('sha256', $payload, $this->key, true)));
    }

    /** @return EntryId|null ревизия, если токен подлинный, не истёк и выдан этому пользователю */
    public function verify(PreviewToken $token, string $accountId): ?EntryId
    {
        $payload = substr($token->toNative(), 0, -43);
        $sig = substr($token->toNative(), -43);
        if (!hash_equals(self::b64(hash_hmac('sha256', $payload, $this->key, true)), $sig)) {
            return null;
        }
        $data = json_decode((string) base64_decode(strtr($payload, '-_', '+/'), true), true, 3);
        if (!is_array($data) || !is_string($data[0] ?? null) || !is_string($data[1] ?? null) || !is_int($data[2] ?? null)) {
            return null;
        }
        if ($data[2] < $this->clock->now()->getTimestamp() || !hash_equals($data[1], $accountId)) {
            return null;
        }
        return EntryId::tryParse($data[0], $id) ? $id : null;
    }

    private static function b64(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
