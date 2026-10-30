<?php
declare(strict_types=1);

namespace Bastion\Http\Controller;

use Bastion\Audit\Domain\{AuditAction, AuditTrail};
use Bastion\Comments\Application\PostComment;
use Bastion\Comments\Domain\{Comment, CommentId, CommentStatus, RejectedComment};
use Bastion\Comments\Infrastructure\CommentRepository;
use Bastion\Content\Domain\EntryId;
use Bastion\Content\Infrastructure\EntryRepository;
use Bastion\Http\Middleware\RequireStaff;
use Bastion\Http\View;
use Bastion\IdentityAccess\Domain\{Account, Capability};
use Bastion\SecurityMonitoring\Domain\{ActorKey, AppSensor, DetectionPoint};
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};
use Psr\Http\Message\{ResponseInterface, ServerRequestInterface};

#[AssetId('bastion-app')]
final class CommentController
{
    public function __construct(
        private readonly PostComment $post,
        private readonly CommentRepository $comments,
        private readonly EntryRepository $entries,
        private readonly PublicController $public,
        private readonly View $view,
        private readonly AppSensor $sensor,
        private readonly AuditTrail $audit,
    ) {
    }

    /** POST /comments — анонимно; защищён HoneypotMiddleware (подписанная метка времени), не CSRF-сессией. */
    public function store(ServerRequestInterface $request): ResponseInterface
    {
        // HoneypotMiddleware работает в режиме пометки: решение и сигнал AppSensor — здесь.
        if ($request->getAttribute('honeypot_violation') === true) {
            $this->sensor->event(DetectionPoint::UT2, ActorKey::ip($this->ip($request)));
            return $this->view->theme('not-found', ['site' => ['name' => 'Bastion']], 403);
        }
        $entry = EntryId::tryParse(Input::string($request, 'entry', 36), $id) ? $this->entries->find($id) : null;
        if ($entry === null || !$entry->isPublished()) {
            return $this->view->theme('not-found', ['site' => ['name' => 'Bastion']], 404);
        }
        $author = Input::string($request, 'author', 300);
        $body = Input::string($request, 'body', 20000);
        try {
            $this->post->post($entry, $author, $body, $this->ip($request));
        } catch (RejectedComment $e) {
            return $this->public->render($entry, ['error' => $e->userMessage(), 'author' => $author, 'body' => $body], 422);
        }
        return $this->public->render($entry, ['sent' => true], 200);
    }

    public function queue(ServerRequestInterface $request): ResponseInterface
    {
        if (!$this->account($request)->role->can(Capability::CommentsModerate)) {
            return $this->forbidden($request);
        }
        return $this->view->admin($request, 'comments', [
            'items' => array_map(static fn (Comment $c) => [
                'id' => $c->id->toNative(), 'author' => $c->author, 'lines' => $c->body->lines(),
                'date' => $c->createdAt->format('Y-m-d H:i'), 'links' => $c->body->linkCount(),
            ], $this->comments->pending(100)),
        ]);
    }

    public function approve(ServerRequestInterface $request, CommentId $id): ResponseInterface
    {
        return $this->moderate($request, $id, CommentStatus::Approved);
    }

    public function reject(ServerRequestInterface $request, CommentId $id): ResponseInterface
    {
        return $this->moderate($request, $id, CommentStatus::Rejected);
    }

    public function spam(ServerRequestInterface $request, CommentId $id): ResponseInterface
    {
        return $this->moderate($request, $id, CommentStatus::Spam);
    }

    #[AbuserStory('comment-moderation-bypass')]
    #[Mitigation(cwe: 'CWE-285', description: 'New comments are always Pending; only accounts with comments.moderate change status, via CSRF-protected POST; violations raise AppSensor ACE3')]
    private function moderate(ServerRequestInterface $request, CommentId $id, CommentStatus $status): ResponseInterface
    {
        if (!$this->account($request)->role->can(Capability::CommentsModerate)) {
            return $this->forbidden($request);
        }
        if (!$this->comments->setStatus($id, $status)) {
            return $this->view->admin($request, 'not-found', [], 404);
        }
        $this->audit->record(match ($status) {
            CommentStatus::Approved => AuditAction::CommentApproved,
            CommentStatus::Spam => AuditAction::CommentMarkedSpam,
            default => AuditAction::CommentRejected,
        }, $this->account($request)->getId(), $id->toNative(), $this->ip($request));
        return $this->view->redirect('/admin/comments');
    }

    private function forbidden(ServerRequestInterface $request): ResponseInterface
    {
        $this->sensor->event(DetectionPoint::ACE3, ActorKey::account($this->account($request)->getId()));
        return $this->view->admin($request, 'forbidden', [], 403);
    }

    private function ip(ServerRequestInterface $request): string
    {
        $ip = $request->getServerParams()['REMOTE_ADDR'] ?? '';
        return is_string($ip) ? $ip : '';
    }

    private function account(ServerRequestInterface $request): Account
    {
        $a = $request->getAttribute(RequireStaff::ACCOUNT);
        return $a instanceof Account ? $a : throw new \LogicException('RequireStaff middleware missing');
    }
}
