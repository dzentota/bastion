<?php
declare(strict_types=1);

namespace Bastion\Updates\Domain;

use Bastion\Extensions\Domain\{ExtensionName, ExtensionVersion, PublisherKey};

/**
 * Подписанная запись журнала обновлений (модель Gossamer). Конверт:
 * {"record": "<json>", "signer": "<b64 Ed25519>", "signature": "<b64>"}; подпись — над DOMAIN . record.
 * Подпись проверяется при разборе; права подписанта — в TrustState.
 */
final class LedgerRecord
{
    public const DOMAIN = "bastion-ledger-v1\n";
    private const VENDOR = '/^[a-z][a-z0-9-]{1,38}$/';

    private function __construct(
        public readonly RecordType $type,
        public readonly string $publisher,
        public readonly PublisherKey $signer,
        public readonly ?PublisherKey $key,
        public readonly ?ExtensionName $package,
        public readonly ?ExtensionVersion $version,
        public readonly ?string $digest,
    ) {
    }

    /** @throws InvalidRecord */
    public static function parse(string $envelope): self
    {
        if (strlen($envelope) > 4096) {
            throw new InvalidRecord('Record too large');
        }
        $e = self::json($envelope, ['record', 'signer', 'signature']);
        $record = is_string($e['record']) ? $e['record'] : throw new InvalidRecord('record must be a string');
        $signer = PublisherKey::tryParse($e['signer'], $k) ? $k : throw new InvalidRecord('Invalid signer key');
        $sig = is_string($e['signature']) ? base64_decode($e['signature'], true) : false;
        if ($sig === false || strlen($sig) !== SODIUM_CRYPTO_SIGN_BYTES
            || !sodium_crypto_sign_verify_detached($sig, self::DOMAIN . $record, $signer->raw())) {
            throw new InvalidRecord('Bad record signature');
        }

        $r = self::json($record, null);
        $type = RecordType::tryFrom(is_string($r['type'] ?? null) ? $r['type'] : '') ?? throw new InvalidRecord('Unknown record type');
        $publisher = $r['publisher'] ?? null;
        if (!is_string($publisher) || !preg_match(self::VENDOR, $publisher)) {
            throw new InvalidRecord('Invalid publisher');
        }
        if ($type === RecordType::Release) {
            self::fields($r, ['type', 'publisher', 'package', 'version', 'digest']);
            $package = ExtensionName::tryParse($r['package'], $p) ? $p : throw new InvalidRecord('Invalid package');
            if ($package->vendor() !== $publisher) {
                throw new InvalidRecord('Package belongs to another publisher');
            }
            $digest = is_string($r['digest']) && preg_match('/^[0-9a-f]{128}$/', $r['digest']) ? $r['digest'] : throw new InvalidRecord('Invalid digest');
            return new self($type, $publisher, $signer, null, $package,
                ExtensionVersion::tryParse($r['version'], $v) ? $v : throw new InvalidRecord('Invalid version'), $digest);
        }
        self::fields($r, ['type', 'publisher', 'key']);
        return new self($type, $publisher, $signer,
            PublisherKey::tryParse($r['key'], $key) ? $key : throw new InvalidRecord('Invalid key'), null, null, null);
    }

    /**
     * Для инструмента издателя: подписанный конверт.
     * @param array<string, string> $record
     */
    public static function sign(array $record, #[\SensitiveParameter] string $secretKey): string
    {
        if ($secretKey === '' || strlen($secretKey) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new \InvalidArgumentException('Invalid Ed25519 secret key');
        }
        $json = json_encode($record, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        return json_encode([
            'record' => $json,
            'signer' => base64_encode(sodium_crypto_sign_publickey_from_secretkey($secretKey)),
            'signature' => base64_encode(sodium_crypto_sign_detached(self::DOMAIN . $json, $secretKey)),
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }

    /**
     * @param list<string>|null $exact
     * @return array<string, mixed>
     */
    private static function json(string $s, ?array $exact): array
    {
        try {
            $d = json_decode($s, true, 3, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw new InvalidRecord('Not JSON');
        }
        if (!is_array($d) || array_is_list($d)) {
            throw new InvalidRecord('Not an object');
        }
        if ($exact !== null) {
            self::fields($d, $exact);
        }
        $out = [];
        foreach ($d as $k => $v) {
            $out[is_string($k) ? $k : throw new InvalidRecord('Non-string key')] = $v;
        }
        return $out;
    }

    /**
     * @param array<array-key, mixed> $d
     * @param list<string> $fields
     */
    private static function fields(array $d, array $fields): void
    {
        $keys = array_keys($d);
        sort($keys);
        sort($fields);
        if ($keys !== $fields) {
            throw new InvalidRecord('Unexpected fields');
        }
    }
}
