<?php
declare(strict_types=1);

namespace BastionExt\Acme\Hello;

use Bastion\Extension\Api\{Context, Extension};

/**
 * Пример расширения. В теме: {{ entry.title | acme_hello_shout }}
 * Всё, что доступно расширению, приходит через $context — и только по выданным правам.
 */
final class Plugin implements Extension
{
    public function register(Context $context): void
    {
        $recent = count($context->content()->latest(10));
        $context->helpers()->add('shout', static fn (string $s): string => mb_strtoupper(trim($s)) . '!');
        $context->helpers()->add('recent', static fn (string $s): string => $s . ' (' . $recent . ' recent posts)');
    }
}
