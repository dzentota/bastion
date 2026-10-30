<?php
declare(strict_types=1);

namespace Bastion\Comments\Infrastructure;

use Bastion\Comments\Domain\{Comment, CommentAuthor, CommentBody, CommentId, CommentStatus};
use Bastion\Content\Domain\EntryId;
use Bastion\Infrastructure\Database\Row;
use SecureDb\Db;

final class CommentRepository
{
    public function __construct(private readonly Db $db)
    {
    }

    public function add(Comment $c): void
    {
        $this->db->insert('?_comments', [
            'id' => $c->id->toNative(),
            'entry_id' => $c->entry->toNative(),
            'author' => $c->author->toNative(),
            'body' => $c->body->toNative(),
            'status' => $c->status->value,
            'fingerprint' => $c->fingerprint,
            'created_at' => $c->createdAt->getTimestamp(),
        ]);
    }

    /** @return list<Comment> */
    public function approvedFor(EntryId $entry): array
    {
        return $this->list($this->db->select(
            'SELECT * FROM ?_comments WHERE entry_id = ? AND status = ? ORDER BY created_at ASC LIMIT 500',
            $entry->toNative(), CommentStatus::Approved->value,
        ));
    }

    /** @return list<Comment> */
    public function pending(int $limit): array
    {
        return $this->list($this->db->select(
            'SELECT * FROM ?_comments WHERE status = ? ORDER BY created_at ASC LIMIT ?',
            CommentStatus::Pending->value, max(1, min($limit, 200)),
        ));
    }

    public function countPending(): int
    {
        return Row::of($this->db->selectRow('SELECT COUNT(*) AS n FROM ?_comments WHERE status = ?', CommentStatus::Pending->value))->int('n');
    }

    public function countSince(string $fingerprint, int $since): int
    {
        return Row::of($this->db->selectRow(
            'SELECT COUNT(*) AS n FROM ?_comments WHERE fingerprint = ? AND created_at > ?', $fingerprint, $since,
        ))->int('n');
    }

    public function setStatus(CommentId $id, CommentStatus $status): bool
    {
        return $this->db->update('?_comments', ['status' => $status->value], ['id' => $id->toNative()]) === 1;
    }

    /**
     * @param array<mixed> $rows
     * @return list<Comment>
     */
    private function list(array $rows): array
    {
        return array_values(array_map(static function (mixed $raw): Comment {
            $r = Row::of($raw);
            return new Comment(
                CommentId::fromNative($r->str('id')),
                EntryId::fromNative($r->str('entry_id')),
                CommentAuthor::fromNative($r->str('author')),
                CommentBody::fromNative($r->str('body')),
                CommentStatus::from($r->str('status')),
                $r->str('fingerprint'),
                (new \DateTimeImmutable())->setTimestamp($r->int('created_at')),
            );
        }, $rows));
    }
}
