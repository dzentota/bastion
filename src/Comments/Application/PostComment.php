<?php
declare(strict_types=1);

namespace Bastion\Comments\Application;

use Bastion\Comments\Domain\{Comment, CommentAuthor, CommentBody, CommenterFingerprint, CommentId, CommentStatus, RejectedComment};
use Bastion\Comments\Infrastructure\CommentRepository;
use Bastion\Content\Domain\Entry;
use Bastion\SecurityMonitoring\Domain\{ActorKey, AppSensor, DetectionPoint};
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};
use Psr\Clock\ClockInterface;

/**
 * Приём анонимного комментария. Всё новое — в статусе Pending; публикует только модератор.
 */
#[AssetId('bastion-app')]
#[AbuserStory('comment-spam-flood')]
#[Mitigation(cwe: 'CWE-770', description: 'Per-source limit (keyed IP hash), bounded moderation queue, link-heavy comments auto-marked spam; AppSensor UT2')]
#[Mitigation(cwe: 'CWE-799', description: 'Signed-timestamp honeypot (dzentota/router HoneypotMiddleware) rejects bots that submit instantly, replay forms or fill trap fields')]
#[AbuserStory('comment-impersonation')]
#[Mitigation(cwe: 'CWE-451', description: 'Names: no control, bidi or invisible characters; NFKC/case-folded comparison against reserved staff names')]
final class PostComment
{
    /** @param list<string> $reservedNames comparisonKey-форма имён сотрудников и служебных слов */
    public function __construct(
        private readonly CommentRepository $comments,
        private readonly CommenterFingerprint $fingerprint,
        private readonly CommentPolicy $policy,
        private readonly AppSensor $sensor,
        private readonly ClockInterface $clock,
        private readonly array $reservedNames,
    ) {
    }

    public function post(Entry $entry, string $rawAuthor, string $rawBody, string $ip): Comment
    {
        if (!$entry->isPublished()) {
            throw new RejectedComment(RejectedComment::CLOSED);
        }
        $source = ActorKey::ip($ip);
        if (!CommentAuthor::tryParse($rawAuthor, $author) || !CommentBody::tryParse(str_replace("\r\n", "\n", $rawBody), $body)) {
            $this->sensor->event(DetectionPoint::IE2, $source);
            throw new RejectedComment(RejectedComment::INVALID);
        }
        if (in_array($author->comparisonKey(), $this->reservedNames, true)) {
            throw new RejectedComment(RejectedComment::RESERVED_NAME);
        }

        $now = $this->clock->now();
        $fp = $this->fingerprint->of($ip);
        if ($this->comments->countSince($fp, $now->getTimestamp() - $this->policy->windowSeconds) >= $this->policy->maxPerSourcePerWindow) {
            $this->sensor->event(DetectionPoint::UT2, $source);
            throw new RejectedComment(RejectedComment::RATE_LIMIT);
        }
        if ($this->comments->countPending() >= $this->policy->maxPendingQueue) {
            throw new RejectedComment(RejectedComment::QUEUE_FULL);
        }

        $status = $body->linkCount() >= $this->policy->spamLinkThreshold ? CommentStatus::Spam : CommentStatus::Pending;
        $comment = new Comment(CommentId::generate(), $entry->id, $author, $body, $status, $fp, $now);
        $this->comments->add($comment);
        return $comment;
    }
}
