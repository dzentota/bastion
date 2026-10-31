<?php
declare(strict_types=1);

namespace Bastion\Http\Controller;

use Bastion\Content\Domain\Slug;
use Bastion\Http\{SiteContext, View};
use Bastion\Shared\I18n\StringCatalog;
use Bastion\ThreatModel\Infrastructure\ThreatModelSource;
use Bastion\ThreatModel\Rendering\ThreatModelViews;
use Bastion\Theming\Dsl\{SafeHtml, TrustedHtmlToken};
use Psr\Http\Message\ResponseInterface;

/** Публичные страницы модели угроз: сводная /{lang}/threats и страница Abuser Story /{lang}/threats/{id}. */
final class ThreatController
{
    public function __construct(
        private readonly ThreatModelSource $source,
        private readonly SiteContext $site,
        private readonly StringCatalog $catalog,
        private readonly View $view,
        private readonly PublicController $public,
        private readonly TrustedHtmlToken $token,
    ) {
    }

    public function index(Slug $lang): ResponseInterface
    {
        $language = $this->site->languages->resolve($lang->toNative());
        if ($language === null) {
            return $this->public->notFound();
        }
        $views = new ThreatModelViews($this->catalog->strings('theme', $language), $language->toNative());
        $m = $this->source->get();
        return $this->view->theme('threats', [
            'site' => $this->site->for($language),
            'entry' => ['title' => $this->catalog->strings('theme', $language)['tm_title'] ?? 'Threat model'],
            'overview' => new SafeHtml($views->render('overview', $m), $this->token),
            'dfd' => new SafeHtml($m !== null ? $views->render('dfd', $m) : '', $this->token),
            'matrix' => new SafeHtml($m !== null ? $views->render('matrix', $m) : '', $this->token),
            'findings' => new SafeHtml($m !== null ? $views->render('findings', $m) : '', $this->token),
        ]);
    }

    public function story(Slug $lang, Slug $slug): ResponseInterface
    {
        $language = $this->site->languages->resolve($lang->toNative());
        $m = $this->source->get();
        $s = $language !== null ? $m?->story($slug->toNative()) : null;
        if ($language === null || $m === null || $s === null) {
            return $this->public->notFound();
        }
        $views = new ThreatModelViews($this->catalog->strings('theme', $language), $language->toNative());
        return $this->view->theme('threat', [
            'site' => $this->site->for($language),
            'entry' => ['title' => $s['title']],
            'index' => '/' . $language->toNative() . '/threats',
            'story' => [
                'id' => $s['id'], 'title' => $s['title'], 'as_a' => $s['asA'], 'i_want' => $s['iWant'], 'so_that' => $s['soThat'],
                'actor' => $m->componentName($s['actor']),
                'assets' => array_map($m->componentName(...), $s['assets']),
                'status' => new SafeHtml($views->status($s['status']), $this->token),
                'cwes' => array_map(static fn (string $c) => ['id' => $c, 'url' => 'https://cwe.mitre.org/data/definitions/' . substr($c, 4) . '.html'], $s['requiredCwes']),
                'missing' => $s['missingCwes'],
                'mitigations' => array_map(static fn (array $x) => ['cwe' => $x['cwe'], 'description' => $x['description'],
                    'where' => $x['file'] . ($x['line'] > 0 ? ':' . $x['line'] : ''), 'symbol' => $x['symbol']], $s['mitigations']),
                'tests' => array_map(static fn (array $x) => ['file' => $x['file'], 'class' => $x['class']], $s['tests']),
            ],
        ]);
    }
}
