<?php
declare(strict_types=1);

namespace Bastion\Theming\Dsl;

/** Подпись кэша AST не сошлась: кто-то писал в кэш. Сигнал для AppSensor. */
final class CacheTampered extends \RuntimeException
{
}
