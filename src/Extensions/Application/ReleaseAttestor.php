<?php
declare(strict_types=1);

namespace Bastion\Extensions\Application;

use Bastion\Extensions\Domain\{InvalidPackage, Manifest};

/** Внешнее подтверждение релиза (журнал обновлений, ADR-0014). Без него сайт работает в Degraded Mode. */
interface ReleaseAttestor
{
    /** @throws InvalidPackage */
    public function attest(Manifest $manifest, string $zipBytes): void;

    /** Новый ключ издателя допустим, только если журнал подтверждает ротацию. */
    public function allowsRotation(Manifest $previous, Manifest $next): bool;
}
