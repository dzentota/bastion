<?php
declare(strict_types=1);

namespace Bastion\Http\Controller;

use Bastion\Content\Domain\{Entry, Slug};
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
        return $this->view->theme('entry', [
            'site' => ['name' => 'Bastion'],
            'entry' => $this->summary($entry) + ['body' => $this->blocks->render($entry->blocks())],
        ]);
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
