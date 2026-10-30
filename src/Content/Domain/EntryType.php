<?php
declare(strict_types=1);

namespace Bastion\Content\Domain;

enum EntryType: string
{
    case Post = 'post';
    case Page = 'page';
}
