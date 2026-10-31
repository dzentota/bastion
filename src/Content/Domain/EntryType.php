<?php
declare(strict_types=1);

namespace Bastion\Content\Domain;

enum EntryType: string
{
    case Post = 'post';
    case Page = 'page';

    /** Страницы — постоянный контент вне ленты: без рубрик, тегов и комментариев. */
    public function inFeed(): bool
    {
        return $this === self::Post;
    }
}
