<?php
declare(strict_types=1);

namespace Bastion\Updates\Application;

use Bastion\Extensions\Domain\PublisherKey;
use Bastion\Updates\Domain\InvalidRecord;

/**
 * Ответ Chronicle: тело подписано ключом сервера (заголовок Body-Signature-Ed25519),
 * записи образуют хэш-цепочку hash = BLAKE2b-256(contents, key: prev) и обязаны продолжать
 * уже принятую голову — подмена истории, форк или откат журнала отвергаются целиком.
 */
final class ChronicleFeed
{
    public const MAX_BODY = 1024 * 1024;
    private const MAX_ENTRIES = 500;

    public static function hash(string $prevHash, string $contents): string
    {
        $key = $prevHash === '' ? '' : self::b64urlDecode($prevHash);
        return rtrim(strtr(base64_encode(sodium_crypto_generichash($contents, $key)), '+/', '-_'), '=');
    }

    /**
     * @return list<array{hash: string, contents: string}>
     * @throws InvalidRecord
     */
    public static function verify(string $body, string $signatureHeader, PublisherKey $serverKey, string $head): array
    {
        $sig = base64_decode(trim($signatureHeader), true);
        if (strlen($body) > self::MAX_BODY || $sig === false || strlen($sig) !== SODIUM_CRYPTO_SIGN_BYTES
            || !sodium_crypto_sign_verify_detached($sig, $body, $serverKey->raw())) {
            throw new InvalidRecord('Chronicle response signature is invalid');
        }
        try {
            $d = json_decode($body, true, 4, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw new InvalidRecord('Chronicle response is not JSON');
        }
        $results = is_array($d) && ($d['status'] ?? null) === 'OK' && is_array($d['results'] ?? null) ? $d['results'] : throw new InvalidRecord('Chronicle response has no results');
        if (count($results) > self::MAX_ENTRIES) {
            throw new InvalidRecord('Too many Chronicle entries in one response');
        }
        $out = [];
        $prev = $head;
        foreach ($results as $e) {
            if (!is_array($e) || !is_string($e['contents'] ?? null) || !is_string($e['prev'] ?? null) || !is_string($e['hash'] ?? null)) {
                throw new InvalidRecord('Malformed Chronicle entry');
            }
            if (!hash_equals($prev, $e['prev']) || !hash_equals(self::hash($prev, $e['contents']), $e['hash'])) {
                throw new InvalidRecord('Chronicle hash chain is broken (rewritten or forked history)');
            }
            $out[] = ['hash' => $e['hash'], 'contents' => $e['contents']];
            $prev = $e['hash'];
        }
        return $out;
    }

    private static function b64urlDecode(string $s): string
    {
        $raw = base64_decode(strtr($s, '-_', '+/'), true);
        return $raw !== false && strlen($raw) === 32 ? $raw : throw new InvalidRecord('Invalid Chronicle hash');
    }
}
