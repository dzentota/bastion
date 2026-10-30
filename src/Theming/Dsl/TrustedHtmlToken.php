<?php
declare(strict_types=1);

namespace Bastion\Theming\Dsl;

/**
 * Капабилити-токен: его наличие = право создавать SafeHtml.
 *
 * Выдаётся только корнем композиции (Http\Kernel) и передаётся ядру через DI.
 * Расширения его не получают: Static Gate расширений (ADR-0012) запрещает любые
 * ссылки на этот класс и на SafeHtml, так что получить токен в обход DI нельзя.
 */
final class TrustedHtmlToken
{
    private function __construct()
    {
    }

    /** @internal только для Http\Kernel и тестов */
    public static function issue(): self
    {
        return new self();
    }

    /** @internal только для тестов */
    public static function forTesting(): self
    {
        return new self();
    }
}
