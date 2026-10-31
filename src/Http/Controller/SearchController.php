<?php
declare(strict_types=1);

namespace Bastion\Http\Controller;

use Bastion\Content\Domain\Slug;
use Bastion\Http\{SiteContext, View};
use Bastion\Search\Domain\{SearchHit, SearchIndex, SearchQuery};
use Bastion\Theming\Dsl\{SafeHtml, TrustedHtmlToken};
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};
use Psr\Http\Message\{ResponseInterface, ServerRequestInterface};

/** /{lang}/search?q=… — поиск по опубликованным записям языка. Запросы не журналируются. */
#[AssetId('bastion-app')]
final class SearchController
{
    public function __construct(
        private readonly SearchIndex $index,
        private readonly SiteContext $site,
        private readonly View $view,
        private readonly PublicController $public,
        private readonly TrustedHtmlToken $token,
    ) {
    }

    #[AbuserStory('search-reflected-xss')]
    #[Mitigation(cwe: 'CWE-79', description: 'The query is echoed only through the escaping template; snippets are escaped first and only the private-use match markers are turned into <mark>')]
    public function search(ServerRequestInterface $request, Slug $lang): ResponseInterface
    {
        $language = $this->site->languages->resolve($lang->toNative());
        if ($language === null) {
            return $this->public->notFound();
        }
        $raw = $request->getQueryParams()['q'] ?? '';
        $query = SearchQuery::parse($raw);
        $hits = $query !== null ? $this->index->search($language, $query) : [];
        $res = $this->view->theme('search', [
            'site' => $this->site->for($language) + ['query' => $query->text ?? ''],
            'entry' => ['title' => $query->text ?? ''],
            'searched' => is_string($raw) && $raw !== '',
            'too_long' => is_string($raw) && strlen($raw) > SearchQuery::MAX_BYTES,
            'results' => array_map(fn (SearchHit $h) => [
                'title' => $h->title, 'url' => '/' . $language->toNative() . '/' . $h->slug,
                'snippet' => new SafeHtml($this->highlight($h->snippet), $this->token),
            ], $hits),
        ]);
        // результаты поиска не индексируются и не кэшируются общими кэшами
        return $res->withHeader('X-Robots-Tag', 'noindex');
    }

    private function highlight(string $snippet): string
    {
        $safe = htmlspecialchars($snippet, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
        $html = str_replace([SearchHit::MARK_OPEN, SearchHit::MARK_CLOSE], ['<mark>', '</mark>'], $safe);
        // непарный маркер (обрезанный отрывок) не должен оставить открытый тег
        return substr_count($html, '<mark>') === substr_count($html, '</mark>') ? $html : str_replace(['<mark>', '</mark>'], '', $html);
    }
}
