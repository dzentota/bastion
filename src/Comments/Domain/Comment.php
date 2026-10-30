<?php
declare(strict_types=1);

namespace Bastion\Comments\Domain;

use Bastion\Content\Domain\EntryId;

final class Comment
{
    public function __construct(
        public readonly CommentId $id,
        public readonly EntryId $entry,
        public readonly CommentAuthor $author,
        public readonly CommentBody $body,
        public readonly CommentStatus $status,
        public readonly string $fingerprint,
        public readonly \DateTimeImmutable $createdAt,
    ) {
    }
}
