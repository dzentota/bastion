<?php
declare(strict_types=1);

namespace Bastion\Theming\Dsl;

/**
 * HTML, сгенерированный доверенным кодом ядра (например, рендерером блоков).
 * Единственный способ вывести неэкранированную разметку из шаблона.
 * Создаётся только через TrustedHtmlFactory — шаблоны и расширения его не получают.
 */
final class SafeHtml
{
    /** @internal используйте TrustedHtmlFactory */
    public function __construct(private readonly string $html, TrustedHtmlToken $token)
    {
    }

    public function toString(): string
    {
        return $this->html;
    }
}
