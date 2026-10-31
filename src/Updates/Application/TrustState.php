<?php
declare(strict_types=1);

namespace Bastion\Updates\Application;

use Bastion\Extensions\Domain\{ExtensionName, ExtensionVersion, PublisherKey};
use Bastion\Updates\Domain\{LedgerRecord, RecordType};

/**
 * Состояние доверия, выведенное из журнала по порядку записей. Правила:
 *  - key-append: подписан активным ключом издателя; первый ключ издателя — самоподписанный;
 *  - key-revoke: подписан другим активным ключом издателя или ключом Super Provider; отзыв окончателен;
 *  - release: подписан ключом, активным на момент записи; одна версия — один digest навсегда.
 * Записи, нарушающие правила, игнорируются (журнал публичный — писать в него может кто угодно).
 */
final class TrustState
{
    /** @var array<string, array<string, bool>> publisher => key => active */
    private array $keys = [];
    /** @var array<string, array{digest: string, signer: string}> "package@version" */
    private array $releases = [];

    public function __construct(private readonly ?PublisherKey $superProvider)
    {
    }

    public function apply(LedgerRecord $r): bool
    {
        $signer = $r->signer->toNative();
        $own = $this->keys[$r->publisher] ?? [];
        $signerActive = ($own[$signer] ?? false) === true;
        switch ($r->type) {
            case RecordType::KeyAppend:
                $key = (string) $r->key?->toNative();
                $bootstrap = $own === [] && $signer === $key;
                if ((!$signerActive && !$bootstrap) || isset($own[$key])) {
                    return false; // повторно добавить отозванный ключ нельзя
                }
                $this->keys[$r->publisher][$key] = true;
                return true;
            case RecordType::KeyRevoke:
                $key = (string) $r->key?->toNative();
                $bySuper = $this->superProvider !== null && hash_equals($this->superProvider->toNative(), $signer);
                if (($own[$key] ?? false) !== true || (!$bySuper && (!$signerActive || $signer === $key))) {
                    return false;
                }
                $this->keys[$r->publisher][$key] = false;
                return true;
            case RecordType::Release:
                $id = $r->package?->toNative() . '@' . $r->version?->toNative();
                if (!$signerActive || isset($this->releases[$id])) {
                    return false;
                }
                $this->releases[$id] = ['digest' => (string) $r->digest, 'signer' => $signer];
                return true;
        }
    }

    public function isActive(string $publisher, PublisherKey $key): bool
    {
        return ($this->keys[$publisher][$key->toNative()] ?? false) === true;
    }

    public function isRevoked(string $publisher, PublisherKey $key): bool
    {
        return ($this->keys[$publisher][$key->toNative()] ?? null) === false;
    }

    /** null — релиз засвидетельствован; иначе причина отказа. */
    public function attest(ExtensionName $package, ExtensionVersion $version, string $digestHex, PublisherKey $signedWith): ?string
    {
        $rel = $this->releases[$package->toNative() . '@' . $version->toNative()] ?? null;
        if ($rel === null) {
            return 'Release is not recorded in the update ledger';
        }
        if (!hash_equals($rel['digest'], $digestHex)) {
            return 'Package digest differs from the one recorded in the update ledger';
        }
        if (!hash_equals($rel['signer'], $signedWith->toNative()) || !$this->isActive($package->vendor(), $signedWith)) {
            return 'Package is signed with a key that is not active in the update ledger';
        }
        return null;
    }
}
