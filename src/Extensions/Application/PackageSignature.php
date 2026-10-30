<?php
declare(strict_types=1);

namespace Bastion\Extensions\Application;

use Bastion\Extensions\Domain\PublisherKey;

/**
 * Подпись пакета: Ed25519 над BLAKE2b-512 всего ZIP (как Halite File::sign в Airship).
 * Подписан архив целиком, включая манифест, так что ни один байт нельзя изменить.
 */
final class PackageSignature
{
    public static function digest(string $zipBytes): string
    {
        return sodium_crypto_generichash($zipBytes, '', SODIUM_CRYPTO_GENERICHASH_BYTES_MAX);
    }

    public static function sign(string $zipBytes, #[\SensitiveParameter] string $secretKey): string
    {
        if (strlen($secretKey) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new \InvalidArgumentException('Invalid Ed25519 secret key');
        }
        return base64_encode(sodium_crypto_sign_detached(self::digest($zipBytes), $secretKey));
    }

    public static function verify(string $zipBytes, string $signatureB64, PublisherKey $key): bool
    {
        $sig = base64_decode(trim($signatureB64), true);
        $pk = $key->raw();
        return $sig !== false && strlen($sig) === SODIUM_CRYPTO_SIGN_BYTES && $pk !== ''
            && sodium_crypto_sign_verify_detached($sig, self::digest($zipBytes), $pk);
    }
}
