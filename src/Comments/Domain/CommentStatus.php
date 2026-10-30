<?php
declare(strict_types=1);

namespace Bastion\Comments\Domain;

enum CommentStatus: string
{
    case Pending = 'pending';
    case Approved = 'approved';
    case Rejected = 'rejected';
    case Spam = 'spam';
}
