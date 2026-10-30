<?php
declare(strict_types=1);

namespace Bastion\Extensions\Domain;

/** Права, которые расширение может запросить в манифесте. */
enum ExtCapability: string
{
    case RenderHelper = 'render.helper';
    case ContentRead = 'content.read';

    public function describe(): string
    {
        return match ($this) {
            self::RenderHelper => 'Add text helpers to theme templates (output is always escaped)',
            self::ContentRead => 'Read titles, links and dates of published posts',
        };
    }
}
