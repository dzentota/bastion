<?php
declare(strict_types=1);

namespace Bastion\Content\Application;

use Bastion\Audit\Domain\{AuditAction, AuditTrail};
use Bastion\Content\Domain\{Entry, EntryType, Language, SiteLanguages, Slug, Title};
use Bastion\Content\Domain\Block\BlockList;
use Bastion\Content\Infrastructure\{EntryRepository, PageTree, RevisionRepository};
use Bastion\Search\Domain\SearchIndex;
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};
use Psr\Clock\ClockInterface;

/**
 * Синхронизация ADR из репозитория в CMS (ADR-0025): docs/adr/NNNN-*.md → страницы «adr-NNNN»
 * под страницей «adr» на языке ADR; переводы — docs/adr/<язык>/NNNN-*.md. Репозиторий — источник
 * истины: записи помечены источником, в CMS только для чтения, каждое изменение — ревизия и публикация.
 */
#[AssetId('bastion-app')]
final class RepositoryDocsSync
{
    public const AUTHOR = 'repo-sync';
    private const INDEX_TITLES = ['ru' => 'Архитектурные решения', 'en' => 'Architecture decisions'];
    private const INDEX_TEXT = [
        'ru' => 'Решения о том, как устроен Bastion и почему. Страницы синхронизируются из каталога docs/adr репозитория и в CMS не редактируются.',
        'en' => 'Decisions about how Bastion is built and why. These pages are synced from the docs/adr directory of the repository and are not edited in the CMS.',
    ];

    public function __construct(
        private readonly EntryRepository $entries,
        private readonly RevisionRepository $revisions,
        private readonly PageTree $tree,
        private readonly SearchIndex $search,
        private readonly SiteLanguages $languages,
        private readonly AuditTrail $audit,
        private readonly ClockInterface $clock,
    ) {
    }

    /**
     * @param string $root корень репозитория/релиза
     * @return list<string> отчёт по строке на файл
     */
    #[AbuserStory('managed-content-override')]
    #[Mitigation(cwe: 'CWE-345', description: 'Only files from docs/adr matching NNNN-name.md are read, never paths from the database; the sync is a CLI-only operation and each change is a signed revision plus an audit entry')]
    public function syncAdrs(string $root, string $sourceLanguage = 'ru'): array
    {
        $base = $this->languages->resolve($sourceLanguage);
        if ($base === null) {
            return ["skip: '{$sourceLanguage}' is not a site language"];
        }
        $report = [];
        $index = $this->indexPage($base, null);
        foreach ($this->files($root . '/docs/adr') as [$n, $file]) {
            $entry = $this->upsert($root, 'docs/adr/' . basename($file), $base, 'adr-' . $n, $index, (int) $n, null, $report);
            foreach ($this->languages->all as $lang) {
                $translated = $root . '/docs/adr/' . $lang->toNative() . '/' . basename($file);
                if ($entry !== null && !$lang->isSame($base) && is_file($translated)) {
                    $this->upsert($root, 'docs/adr/' . $lang->toNative() . '/' . basename($file), $lang, 'adr-' . $n,
                        $this->indexPage($lang, $index), (int) $n, $entry, $report);
                }
            }
        }
        return $report;
    }

    /**
     * @param list<string> $report
     */
    private function upsert(string $root, string $source, Language $lang, string $slug, Entry $parent, int $position, ?Entry $original, array &$report): ?Entry
    {
        try {
            $doc = MarkdownBlocks::parse((string) file_get_contents($root . '/' . $source));
            $title = Title::fromNative($doc['title']);
        } catch (\Throwable $e) {
            $report[] = "error   {$source}: " . $e->getMessage();
            return null;
        }
        return $this->put($source, $lang, Slug::fromNative($slug), $title, $doc['blocks'], $parent, $position, $original, $report);
    }

    /**
     * @param list<string> $report
     */
    private function put(string $source, Language $lang, Slug $slug, Title $title, BlockList $blocks, ?Entry $parent, int $position, ?Entry $original, array &$report): ?Entry
    {
        $entry = $this->entries->findBySource($source);
        if ($entry === null) {
            if ($this->entries->slugTaken($lang, $slug)) {
                $report[] = "error   {$source}: /{$lang->toNative()}/{$slug->toNative()} is used by a page edited in the CMS";
                return null;
            }
            $entry = $original !== null
                ? $original->translate($lang, $title, $slug, self::AUTHOR)
                : Entry::draft(EntryType::Page, $lang, $title, $slug, $blocks, self::AUTHOR);
            $entry->revise($title, $slug, $blocks);
            $this->entries->save($entry);
            $this->entries->markSource($entry->id, $source);
            $state = 'created';
        } else {
            $head = $this->revisions->head($entry->id);
            $state = $head !== null && $head->sameContentAs($title, $slug, $blocks) && $entry->isPublished() ? 'same' : 'updated';
            $entry->revise($title, $slug, $blocks);
        }
        if ($parent !== null && $this->tree->refusal($entry, $parent->id) === null) {
            $this->tree->place($entry->id, $parent->id, $position);
        }
        if ($state !== 'same') {
            $rev = $this->revisions->record($entry, $title, $slug, $blocks, self::AUTHOR);
            $entry->publish($this->clock->now());
            $this->entries->save($entry);
            $this->revisions->markPublished($entry->id, $rev->id);
            $this->search->index($entry);
            $this->audit->record(AuditAction::EntryPublished, null, $entry->id->toNative(), 'cli');
        }
        $report[] = str_pad($state, 8) . $source;
        return $entry;
    }

    /** Страница-оглавление «adr» на языке (тоже под управлением репозитория). */
    private function indexPage(Language $lang, ?Entry $original): Entry
    {
        $code = $lang->toNative();
        $blocks = BlockList::fromJson((string) json_encode([['type' => 'paragraph', 'data' => ['text' => self::INDEX_TEXT[$code] ?? self::INDEX_TEXT['en']]]]));
        $report = [];
        return $this->put('docs/adr#' . $code, $lang, Slug::fromNative('adr'), Title::fromNative(self::INDEX_TITLES[$code] ?? self::INDEX_TITLES['en']), $blocks, null, 0, $original, $report)
            ?? throw new \RuntimeException("/{$code}/adr is used by a page edited in the CMS");
    }

    /** @return list<array{0: string, 1: string}> [номер, путь] по возрастанию; только NNNN-имя.md, без ссылок */
    private function files(string $dir): array
    {
        $out = [];
        foreach (glob($dir . '/*.md') ?: [] as $f) {
            if (preg_match('/^(\d{4})-[a-z0-9-]+\.md$/', basename($f), $m) && is_file($f) && !is_link($f)) {
                $out[] = [$m[1], $f];
            }
        }
        usort($out, static fn (array $a, array $b) => $a[0] <=> $b[0]);
        return $out;
    }
}
