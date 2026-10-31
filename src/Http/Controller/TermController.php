<?php
declare(strict_types=1);

namespace Bastion\Http\Controller;

use Bastion\Content\Domain\{Entry, EntryId, Language, Slug};
use Bastion\Content\Infrastructure\EntryRepository;
use Bastion\Http\{SiteContext, View};
use Bastion\SecurityMonitoring\Domain\{ActorKey, AppSensor, DetectionPoint};
use Bastion\Taxonomy\Domain\{PageNumber, Term, TermKind};
use Bastion\Taxonomy\Infrastructure\TermRepository;
use Psr\Http\Message\{ResponseInterface, ServerRequestInterface};

/** Публичные листинги рубрик и тегов. Abuser story: term-enumeration-dos. */
final class TermController
{
    public function __construct(
        private readonly TermRepository $terms,
        private readonly EntryRepository $entries,
        private readonly View $view,
        private readonly AppSensor $sensor,
        private readonly SiteContext $site,
    ) {
    }

    public function category(ServerRequestInterface $request, Slug $lang, Slug $slug): ResponseInterface
    {
        return $this->listing($request, $lang, new Term(TermKind::Category, $slug));
    }

    public function tag(ServerRequestInterface $request, Slug $lang, Slug $slug): ResponseInterface
    {
        return $this->listing($request, $lang, new Term(TermKind::Tag, $slug));
    }

    /** Старые адреса /category/{slug} и /tag/{slug} → язык по умолчанию. */
    public function movedCategory(Slug $slug): ResponseInterface
    {
        return $this->view->moved((new Term(TermKind::Category, $slug))->url($this->site->languages->default));
    }

    public function movedTag(Slug $slug): ResponseInterface
    {
        return $this->view->moved((new Term(TermKind::Tag, $slug))->url($this->site->languages->default));
    }

    private function listing(ServerRequestInterface $request, Slug $lang, Term $term): ResponseInterface
    {
        $language = $this->site->languages->resolve($lang->toNative());
        if ($language === null) {
            return $this->notFound();
        }
        $query = $request->getQueryParams();
        $raw = $query['page'] ?? '1';
        if (!PageNumber::tryParse($raw, $page)) {
            // запредельные страницы — сигнал перебора, а не повод считать; прочие параметры игнорируются
            $this->sensor->event(DetectionPoint::IE2, ActorKey::ip(is_string($ip = $request->getServerParams()['REMOTE_ADDR'] ?? null) ? $ip : 'unknown'));
            return $this->notFound();
        }
        if (!$this->terms->exists($term->kind, $term->slug)) {
            return $this->notFound();
        }
        $ids = $this->terms->publishedEntryIds($term, $language, $page);
        $more = count($ids) > TermRepository::PAGE_SIZE;
        $posts = [];
        foreach (array_slice($ids, 0, TermRepository::PAGE_SIZE) as $id) {
            $e = $this->entries->find(EntryId::fromNative($id));
            if ($e !== null && $e->isPublished()) {
                $posts[] = ['title' => $e->title(), 'url' => $e->path(), 'date' => $e->publishedAt()?->format('Y-m-d')];
            }
        }
        if ($posts === [] && $page->toInt() > 1) {
            return $this->notFound();
        }
        $n = $page->toInt();
        return $this->view->theme('term', [
            'site' => $this->site->for($language),
            'term' => ['kind' => $term->kind === TermKind::Category ? 'Category' : 'Tag', 'is_category' => $term->kind === TermKind::Category, 'name' => $term->slug],
            'posts' => $posts,
            'prev' => $n > 1 ? $term->url($language) . ($n > 2 ? '?page=' . ($n - 1) : '') : null,
            'next' => $more && $n < PageNumber::MAX ? $term->url($language) . '?page=' . ($n + 1) : null,
        ]);
    }

    private function notFound(): ResponseInterface
    {
        return $this->view->theme('not-found', ['site' => $this->site->default()], 404);
    }
}
