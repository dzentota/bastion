<?php
declare(strict_types=1);

namespace Bastion\Updates\Application;

use Bastion\Extensions\Domain\PublisherKey;

/** Канал обновлений: адреса только https, ключ Chronicle и Super Provider закреплены в конфиге. */
final class UpdateConfig
{
    public function __construct(
        public readonly string $chronicleUrl,
        public readonly PublisherKey $chronicleKey,
        public readonly string $registryUrl,
        public readonly ?PublisherKey $superProvider,
    ) {
        foreach ([$chronicleUrl, $registryUrl] as $url) {
            if (!preg_match('#^https://[a-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$#', $url)) {
                throw new \InvalidArgumentException('Update URLs must be plain https:// URLs');
            }
        }
    }

    /** null — канал не настроен (Degraded Mode: только ручная загрузка с закреплённым ключом). */
    public static function fromRaw(callable $raw): ?self
    {
        $chronicle = $raw('updates.chronicle');
        if (!is_string($chronicle)) {
            return null;
        }
        $str = static fn (string $k): string => is_string($v = $raw($k)) ? $v : throw new \UnexpectedValueException("Config {$k} must be a string");
        $super = $raw('updates.super_key');
        return new self(
            $chronicle,
            PublisherKey::tryParse($str('updates.chronicle_key'), $k) ? $k : throw new \UnexpectedValueException('Config updates.chronicle_key must be an Ed25519 key'),
            $str('updates.registry'),
            is_string($super) ? (PublisherKey::tryParse($super, $sk) ? $sk : throw new \UnexpectedValueException('Config updates.super_key must be an Ed25519 key')) : null,
        );
    }
}
