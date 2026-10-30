<?php
declare(strict_types=1);

namespace Bastion\Http\Controller;

use Bastion\Comments\Domain\Comment;
use Bastion\Comments\Infrastructure\CommentRepository;
use Bastion\Content\Domain\{Entry, Slug};
use dzentota\Router\Middleware\HoneypotMiddleware;
use Bastion\Content\Infrastructure\EntryRepository;
use Bastion\Content\Rendering\BlockHtmlRenderer;
use Bastion\Http\View;
use Psr\Http\Message\ResponseInterface;

final class PublicController
{
    public function __construct(
        private readonly EntryRepository $entries,
        private readonly BlockHtmlRenderer $blocks,
        private readonly View $view,
        private readonly CommentRepository $comments,
        private readonly HoneypotMiddleware $honeypot,
    ) {
    }

    public function home(): ResponseInterface
    {
        return $this->view->theme('home', [
            'site' => ['name' => 'Bastion'],
            'posts' => array_map(fn (Entry $e) => $this->summary($e), $this->entries->latest(20, true)),
        ]);
    }

    public function show(Slug $slug): ResponseInterface
    {
        $entry = $this->entries->findPublishedBySlug($slug);
        if ($entry === null) {
            return $this->view->theme('not-found', ['site' => ['name' => 'Bastion']], 404);
        }
        return $this->render($entry, [], 200);
    }

    /** @param array<string, mixed> $form состояние формы комментария (ошибка, введённые значения, "отправлено") */
    public function render(Entry $entry, array $form, int $status): ResponseInterface
    {
        return $this->view->theme('entry', [
            'site' => ['name' => 'Bastion'],
            'entry' => $this->summary($entry) + ['body' => $this->blocks->render($entry->blocks())],
            'comments' => array_map(static fn (Comment $c) => [
                'author' => $c->author, 'lines' => $c->body->lines(), 'date' => $c->createdAt->format('Y-m-d'),
            ], $this->comments->approvedFor($entry->id)),
            'comment_form' => $form + [
                'entry' => $entry->id->toNative(),
                'timestamp' => $this->honeypot->generateTimestamp(),
            ],
        ], $status);
    }

    /** @return array<string, mixed> */
    private function summary(Entry $e): array
    {
        return [
            'title' => $e->title(),
            'url' => '/' . $e->slug()->toNative(),
            'date' => $e->publishedAt()?->format('Y-m-d'),
        ];
    }
}
