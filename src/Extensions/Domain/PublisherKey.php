<?php
declare(strict_types=1);

namespace Bastion\Extensions\Domain;

use dzentota\TypedValue\Typed;
use dzentota\TypedValue\TypedValue;
use dzentota\TypedValue\ValidationResult;

/**
 * Публичный ключ издателя Ed25519 (base64, 32 байта).
 * @implements Typed<string>
 */
final class PublisherKey implements Typed
{
    /** @use TypedValue<string> */
    use TypedValue;

    public static function validate($value): ValidationResult
    {
        $r = new ValidationResult();
        $raw = is_string($value) ? base64_decode($value, true) : false;
        if ($raw === false || strlen($raw) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            $r->addError('Publisher key must be a base64 Ed25519 public key');
        }
        return $r;
    }

    /** @return non-empty-string */
    public function raw(): string
    {
        $raw = base64_decode((string) $this->value, true);
        return is_string($raw) && $raw !== '' ? $raw : throw new \LogicException('PublisherKey holds an invalid value');
    }

    /** Отпечаток для сверки с сайтом издателя: 16 групп по 4 hex-символа. */
    public function fingerprint(): string
    {
        return implode(':', str_split(substr(hash('sha256', $this->raw()), 0, 64), 4));
    }
}
