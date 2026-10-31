<?php
declare(strict_types=1);

namespace Bastion\Content\Application;

use Bastion\Audit\Domain\{AuditAction, AuditTrail};
use Bastion\Content\Domain\{Entry, EntryType, MenuPosition, SiteLanguages, Slug, Title};
use Bastion\Content\Infrastructure\{EntryRepository, MenuRepository, PageTree, RevisionRepository};
use Bastion\Search\Domain\SearchIndex;
use Psr\Clock\ClockInterface;

/**
 * Стартовое содержимое сайта из docs/site/<язык>/NN-имя.md (ADR-0025). В отличие от ADR, после
 * импорта страницы принадлежат CMS: существующая страница никогда не перезаписывается.
 * Шапка файла:  ---  slug: x  parent: y  menu: 10  ---  затем «# Заголовок» и текст.
 * Одноимённые файлы разных языков становятся переводами друг друга.
 */
final class SiteContentImport
{
    public const AUTHOR = 'site-import';

    public function __construct(
        private readonly EntryRepository $entries,
        private readonly RevisionRepository $revisions,
        private readonly PageTree $tree,
        private readonly MenuRepository $menu,
        private readonly SearchIndex $search,
        private readonly SiteLanguages $languages,
        private readonly AuditTrail $audit,
        private readonly ClockInterface $clock,
    ) {
    }

    /** @return list<string> */
    public function import(string $root): array
    {
        $report = [];
        /** @var array<string, Entry> $byFile первая созданная запись для имени файла — для переводов */
        $byFile = [];
        foreach ($this->languages->all as $lang) {
            $dir = $root . '/docs/site/' . $lang->toNative();
            $files = array_values(array_filter(glob($dir . '/*.md') ?: [], static fn (string $f) => preg_match('/^\d{2}-[a-z0-9-]+\.md$/', basename($f)) === 1 && !is_link($f)));
            sort($files);
            foreach ($files as $file) {
                $name = basename($file);
                $rel = 'docs/site/' . $lang->toNative() . '/' . $name;
                try {
                    [$meta, $body] = self::frontMatter((string) file_get_contents($file));
                    $doc = MarkdownBlocks::parse($body);
                    $slug = Slug::fromNative($meta['slug'] ?? throw new \InvalidArgumentException('no slug'));
                    $title = Title::fromNative($doc['title']);
                } catch (\Throwable $e) {
                    $report[] = "error   {$rel}: " . $e->getMessage();
                    continue;
                }
                if ($this->entries->slugTaken($lang, $slug)) {
                    $report[] = "exists  {$rel} (/{$lang->toNative()}/{$slug->toNative()} is kept as is)";
                    continue;
                }
                $original = $byFile[$name] ?? null;
                $entry = $original !== null ? $original->translate($lang, $title, $slug, self::AUTHOR) : Entry::draft(EntryType::Page, $lang, $title, $slug, $doc['blocks'], self::AUTHOR);
                $entry->revise($title, $slug, $doc['blocks']);
                $entry->publish($this->clock->now());
                $this->entries->save($entry);
                $rev = $this->revisions->record($entry, $title, $slug, $doc['blocks'], self::AUTHOR);
                $this->revisions->markPublished($entry->id, $rev->id);
                $parent = isset($meta['parent']) && Slug::tryParse($meta['parent'], $p) ? $this->entries->findPublishedBySlug($lang, $p) : null;
                if ($parent !== null && $this->tree->refusal($entry, $parent->id) === null) {
                    $this->tree->place($entry->id, $parent->id, (int) substr($name, 0, 2));
                }
                if (isset($meta['menu']) && MenuPosition::tryParse($meta['menu'], $pos)) {
                    $this->menu->place($entry->id, $pos);
                }
                $this->search->index($entry);
                $this->audit->record(AuditAction::EntryPublished, null, $entry->id->toNative(), 'cli');
                $byFile[$name] ??= $entry;
                $report[] = "created {$rel} → /{$lang->toNative()}/{$slug->toNative()}";
            }
        }
        return $report;
    }

    /** @return array{0: array<string, string>, 1: string} */
    private static function frontMatter(string $text): array
    {
        if (!preg_match('/\A---\R(.*?)\R---\R(.*)\z/s', $text, $m)) {
            return [[], $text];
        }
        $meta = [];
        foreach (preg_split('/\R/', $m[1]) ?: [] as $line) {
            if (preg_match('/^(slug|parent|menu):\s*(\S+)\s*$/', $line, $kv)) {
                $meta[$kv[1]] = $kv[2];
            }
        }
        return [$meta, $m[2]];
    }
}
