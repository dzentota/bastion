<?php
declare(strict_types=1);

namespace Bastion\Extension\Api;

/**
 * Публичный API расширений (ADR-0012). Расширение — final-класс, реализующий этот интерфейс.
 * Ядро вызывает register() один раз на запрос; всё, что расширению доступно, приходит через $context.
 */
interface Extension
{
    public function register(Context $context): void;
}
