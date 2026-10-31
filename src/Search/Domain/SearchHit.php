<?php
declare(strict_types=1);

namespace Bastion\Search\Domain;

final class SearchHit
{
    /** @param string $snippet простой текст; совпадения окружены MARK_OPEN … MARK_CLOSE */
    public function __construct(public readonly string $entryId, public readonly string $title, public readonly string $slug, public readonly string $snippet)
    {
    }

    /** Символы частной области Unicode: в тексте записей их не бывает, а экранирование их не трогает. */
    public const MARK_OPEN = "\u{E000}";
    public const MARK_CLOSE = "\u{E001}";
}
