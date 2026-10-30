<?php
declare(strict_types=1);

namespace Bastion\Content\Domain;

enum EntryStatus: string
{
    case Draft = 'draft';
    case Published = 'published';
}
