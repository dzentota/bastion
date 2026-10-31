<?php
declare(strict_types=1);

namespace Bastion\Taxonomy\Domain;

enum TermKind: string
{
    case Category = 'category';
    case Tag = 'tag';

    /** Сколько терминов этого вида можно привязать к одной записи. */
    public function perEntryLimit(): int
    {
        return match ($this) {
            self::Category => 5,
            self::Tag => 15,
        };
    }
}
