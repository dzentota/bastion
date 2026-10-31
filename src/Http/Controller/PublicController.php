<?php
declare(strict_types=1);

namespace Bastion\Http\Controller;

use Bastion\Comments\Domain\Comment;
use Bastion\Comments\Infrastructure\CommentRepository;
use Bastion\Content\Domain\{Entry, Language, Slug};
use dzentota\Router\Middleware\HoneypotMiddleware;
use Bastion\Content\Infrastructure\EntryRepository;
use Bastion\Content\Rendering\BlockHtmlRenderer;
use Bastion\Http\{SiteContext, View};
use Bastion\Taxonomy\Domain\{Term, TermKind};
use Bastion\Taxonomy\Infrastructure\TermRepository;
use Psr\Http\Message\{ResponseInterface, ServerRequestInterface};

final class PublicController
{
    public function __construct(
        private readonly EntryRepository $entries,
        private readonly BlockHtmlRenderer $blocks,
        private readonly View $view,
        private readonly CommentRepository $comments,
        private readonly HoneypotMiddleware $honeypot,
        private readonly TermRepository $terms,
        private readonly SiteContext $site,
        private readonly \Bastion\Content\Infrastructure\PageTree $tree,
    ) {
    }

    /**
     * @param array{title: string, slug: string} $p
     * @return array{title: string, url: string}
     */
    private static function link(string $lang, array $p): array
    {
        return ['title' => $p['title'], 'url' => '/' . $lang . '/' . $p['slug']];
    }

    /**
     * @param list<array{id: string, title: string, slug: string}> $pages
     * @return list<array{title: string, url: string}>
     */
    private static function links(string $lang, array $pages): array
    {
        $out = [];
        foreach ($pages as $p) {
            $out[] = self::link($lang, $p);
        }
        return $out;
    }

    /** @return array<string, mixed> навигация страницы по дереву: крошки, раздел, дети */
    private function treeContext(Entry $entry): array
    {
        if ($entry->type->inFeed()) {
            return [];
        }
        $lang = $entry->lang->toNative();
        $current = $entry->id->toNative();
        $section = $this->tree->publishedSection($entry->id);
        $items = [];
        foreach ($section['items'] as $p) {
            $items[] = self::link($lang, $p) + ['depth' => (string) $p['depth'], 'current' => $p['id'] === $current];
        }
        return [
            'breadcrumbs' => self::links($lang, $this->tree->publishedAncestors($entry->id)),
            'children' => self::links($lang, $this->tree->publishedChildren($entry->id)),
            'section' => $section['root'] !== null && $items !== [] ? [
                'root' => self::link($lang, $section['root']) + ['current' => $section['root']['id'] === $current],
                'items' => $items,
            ] : null,
        ];
    }

    /** / → главная языка по умолчанию. */
    public function root(): ResponseInterface
    {
        return $this->view->redirect('/' . $this->site->languages->default->toNative());
    }

    /**
     * Первый сегмент пути: язык сайта (главная) или slug старого адреса /{slug} → 301.
     * Один маршрут, потому что у дерева маршрутов один параметр на уровень.
     */
    public function first(Slug $lang): ResponseInterface
    {
        $language = $this->site->languages->resolve($lang->toNative());
        if ($language !== null) {
            return $this->view->theme('home', [
                'site' => $this->site->for($language),
                'posts' => array_map(fn (Entry $e) => $this->summary($e), $this->entries->latest(20, true, null, $language)),
            ]);
        }
        $moved = $this->entries->findPublishedBySlugAnyLanguage($lang, $this->site->languages->default);
        return $moved !== null ? $this->view->moved($moved->path()) : $this->notFound();
    }

    public function show(ServerRequestInterface $request, Slug $lang, Slug $slug): ResponseInterface
    {
        $language = $this->site->languages->resolve($lang->toNative());
        $entry = $language !== null ? $this->entries->findPublishedBySlug($language, $slug) : null;
        if ($entry === null) {
            return $this->notFound();
        }
        // только флаг: текст уведомления задан шаблоном
        return $this->render($entry, ($request->getQueryParams()['comment'] ?? null) === 'sent' ? ['sent' => true] : [], 200);
    }

    /** @param array<string, mixed> $form состояние формы комментария (ошибка, введённые значения, "отправлено") */
    public function render(Entry $entry, array $form, int $status): ResponseInterface
    {
        return $this->view->theme('entry', [
            'site' => $this->site->for($entry->lang, $this->entries->translations($entry->translationGroup)),
            'entry' => $this->summary($entry) + ['body' => $this->blocks->render($entry->blocks())] + $this->termLinks($entry),
            'tree' => $this->treeContext($entry),
            'comments_open' => $entry->type->inFeed(),
            'comments' => !$entry->type->inFeed() ? [] : array_map(static fn (Comment $c) => [
                'author' => $c->author, 'lines' => $c->body->lines(), 'date' => $c->createdAt->format('Y-m-d'),
            ], $this->comments->approvedFor($entry->id)),
            'comment_form' => $form + [
                'entry' => $entry->id->toNative(),
                'timestamp' => $this->honeypot->generateTimestamp(),
            ],
        ], $status);
    }

    /** @return array{categories: list<array{name: string, url: string}>, tags: list<array{name: string, url: string}>} */
    private function termLinks(Entry $entry): array
    {
        $links = fn (TermKind $k) => array_map(
            static fn (Term $t) => ['name' => $t->slug->toNative(), 'url' => $t->url($entry->lang)], $this->terms->forEntry($entry->id, $k)->terms,
        );
        return ['categories' => $links(TermKind::Category), 'tags' => $links(TermKind::Tag)];
    }

    /** @return array<string, mixed> */
    private function summary(Entry $e): array
    {
        return [
            'title' => $e->title(),
            'url' => $e->path(),
            'date' => $e->publishedAt()?->format('Y-m-d'),
        ];
    }

    /**
     * Предпросмотр ревизии в теме сайта. Комментарии выключены; страница не индексируется,
     * не кэшируется и не передаёт Referer.
     */
    #[\HybridTM\Attributes\AbuserStory('preview-exposure')]
    #[\HybridTM\Attributes\Mitigation(cwe: 'CWE-200', description: 'Preview responses carry X-Robots-Tag noindex, Cache-Control no-store and Referrer-Policy no-referrer, and live under /admin behind RequireStaff')]
    public function preview(Entry $transient): ResponseInterface
    {
        $res = $this->view->theme('entry', [
            'site' => $this->site->for($transient->lang),
            'preview' => true,
            'entry' => $this->summary($transient) + ['body' => $this->blocks->render($transient->blocks())] + $this->termLinks($transient),
            'tree' => $this->treeContext($transient),
            'comments_open' => false,
            'comments' => [],
            'comment_form' => [],
        ]);
        return $res->withHeader('X-Robots-Tag', 'noindex, nofollow')->withHeader('Cache-Control', 'no-store')->withHeader('Referrer-Policy', 'no-referrer');
    }

    public function notFound(): ResponseInterface
    {
        return $this->view->theme('not-found', ['site' => $this->site->default()], 404);
    }
}
