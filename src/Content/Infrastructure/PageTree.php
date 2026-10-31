<?php
declare(strict_types=1);

namespace Bastion\Content\Infrastructure;

use Bastion\Content\Domain\{Entry, EntryId, EntryStatus, EntryType, Language};
use Bastion\Infrastructure\Database\Row;
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};
use SecureDb\Db;

/**
 * Дерево страниц. URL от дерева не зависят (/{язык}/{slug}), поэтому перенос страницы
 * не ломает ссылки. Глубина ограничена, циклы невозможны: проверка при каждом переносе.
 */
#[AssetId('bastion-app')]
#[AbuserStory('page-tree-cycle')]
#[Mitigation(cwe: 'CWE-835', description: 'Parent must be another page in the same language; ancestors are walked with a hard depth bound and a move that creates a cycle or exceeds MAX_DEPTH is refused; all traversals are depth-bounded')]
final class PageTree
{
    public const MAX_DEPTH = 4;
    public const MAX_CHILDREN = 100;

    public function __construct(private readonly Db $db)
    {
    }

    /** Почему перенос невозможен (null — можно). Ключ — английский текст для каталога messages. */
    public function refusal(Entry $page, ?EntryId $parent): ?string
    {
        if ($parent === null) {
            return $this->height($page->id) > self::MAX_DEPTH ? 'The page tree would be too deep (at most 4 levels).' : null;
        }
        if ($page->type !== EntryType::Page) {
            return 'Only pages can have a parent page.';
        }
        $row = $this->db->selectRow('SELECT type, lang FROM ?_entries WHERE id = ?', $parent->toNative());
        if (!$row || Row::of($row)->str('type') !== EntryType::Page->value || Row::of($row)->str('lang') !== $page->lang->toNative()) {
            return 'The parent must be a page in the same language.';
        }
        $ancestors = $this->ancestorIds($parent);
        if ($parent->isSame($page->id) || in_array($page->id->toNative(), $ancestors, true)) {
            return 'A page cannot be placed inside itself.';
        }
        // глубина родителя + высота переносимого поддерева
        if (count($ancestors) + 1 + $this->height($page->id) > self::MAX_DEPTH) {
            return 'The page tree would be too deep (at most 4 levels).';
        }
        return null;
    }

    public function place(EntryId $page, ?EntryId $parent, int $position): void
    {
        $this->db->update('?_entries', ['parent_id' => $parent?->toNative(), 'position' => max(0, min($position, 999))], ['id' => $page->toNative()]);
    }

    /** @return array{parent: ?string, position: int} */
    public function placement(EntryId $page): array
    {
        $r = Row::of($this->db->selectRow('SELECT parent_id, position FROM ?_entries WHERE id = ?', $page->toNative()) ?: ['parent_id' => null, 'position' => 0]);
        return ['parent' => $r->nullableStr('parent_id'), 'position' => $r->int('position')];
    }

    /** @return list<string> id предков от родителя к корню (не больше MAX_DEPTH + 1 шагов) */
    public function ancestorIds(EntryId $page): array
    {
        $ids = [];
        $current = $page->toNative();
        for ($i = 0; $i <= self::MAX_DEPTH; $i++) {
            $parent = $this->db->selectCell('SELECT parent_id FROM ?_entries WHERE id = ?', $current);
            if (!is_string($parent) || in_array($parent, $ids, true)) {
                break;
            }
            $ids[] = $parent;
            $current = $parent;
        }
        return $ids;
    }

    /** @return list<array{id: string, title: string, slug: string}> опубликованные дети по порядку */
    public function publishedChildren(EntryId $page): array
    {
        return $this->rows($this->db->select(
            'SELECT id, title, slug FROM ?_entries WHERE parent_id = ? AND status = ? AND type = ? ORDER BY position, title LIMIT ?',
            $page->toNative(), EntryStatus::Published->value, EntryType::Page->value, self::MAX_CHILDREN,
        ));
    }

    /** @return list<array{id: string, title: string, slug: string}> опубликованные предки от корня к родителю */
    public function publishedAncestors(EntryId $page): array
    {
        $out = [];
        foreach ($this->ancestorIds($page) as $id) {
            $row = $this->db->selectRow('SELECT id, title, slug FROM ?_entries WHERE id = ? AND status = ?', $id, EntryStatus::Published->value);
            if (!$row) {
                break; // неопубликованный предок обрывает цепочку: его заголовок не раскрывается
            }
            $out[] = $this->rows([$row])[0];
        }
        return array_reverse($out);
    }

    /**
     * Раздел документации для боковой навигации: корень раздела и его опубликованные потомки.
     * @return array{root: ?array{id: string, title: string, slug: string}, items: list<array{id: string, title: string, slug: string, depth: int}>}
     */
    public function publishedSection(EntryId $page): array
    {
        $ancestors = $this->ancestorIds($page);
        $rootId = $ancestors === [] ? $page->toNative() : $ancestors[count($ancestors) - 1];
        $root = $this->db->selectRow('SELECT id, title, slug FROM ?_entries WHERE id = ? AND status = ?', $rootId, EntryStatus::Published->value);
        $items = [];
        $walk = function (string $id, int $depth) use (&$walk, &$items): void {
            if ($depth > self::MAX_DEPTH || count($items) >= 300) {
                return;
            }
            foreach ($this->publishedChildren(EntryId::fromNative($id)) as $child) {
                $items[] = $child + ['depth' => $depth];
                $walk($child['id'], $depth + 1);
            }
        };
        $walk($rootId, 1);
        return ['root' => $root ? $this->rows([$root])[0] : null, 'items' => $items];
    }

    /** @return list<array{id: string, title: string, slug: string, depth: int}> страницы языка деревом (для выбора родителя) */
    public function outline(Language $lang): array
    {
        $rows = $this->db->select('SELECT id, title, slug, parent_id FROM ?_entries WHERE lang = ? AND type = ? ORDER BY position, title LIMIT 500',
            $lang->toNative(), EntryType::Page->value);
        $byParent = [];
        foreach ($rows as $raw) {
            $r = Row::of($raw);
            $byParent[$r->nullableStr('parent_id') ?? ''][] = ['id' => $r->str('id'), 'title' => $r->str('title'), 'slug' => $r->str('slug')];
        }
        $ids = array_column(array_merge(...array_values($byParent ?: [[]])), 'id');
        $out = [];
        $walk = function (string $parent, int $depth) use (&$walk, &$out, $byParent): void {
            if ($depth > self::MAX_DEPTH) {
                return;
            }
            foreach ($byParent[$parent] ?? [] as $p) {
                $out[] = $p + ['depth' => $depth];
                $walk($p['id'], $depth + 1);
            }
        };
        $walk('', 0);
        // сироты (родитель удалён или в другом языке) — на верхний уровень
        foreach ($byParent as $parent => $children) {
            if ($parent !== '' && !in_array($parent, $ids, true)) {
                foreach ($children as $p) {
                    $out[] = $p + ['depth' => 0];
                }
            }
        }
        return $out;
    }

    /** Высота поддерева страницы (1 — без детей), с жёстким пределом. */
    private function height(EntryId $page): int
    {
        $level = [$page->toNative()];
        for ($h = 1; $h <= self::MAX_DEPTH + 1; $h++) {
            $next = [];
            foreach ($level as $id) {
                foreach ($this->db->selectCol('SELECT id FROM ?_entries WHERE parent_id = ? LIMIT ?', $id, self::MAX_CHILDREN) as $child) {
                    if (is_string($child)) {
                        $next[] = $child;
                    }
                }
            }
            if ($next === []) {
                return $h;
            }
            $level = $next;
        }
        return self::MAX_DEPTH + 2;
    }

    /**
     * @param array<mixed> $rows
     * @return list<array{id: string, title: string, slug: string}>
     */
    private function rows(array $rows): array
    {
        return array_values(array_map(static function (mixed $raw): array {
            $r = Row::of($raw);
            return ['id' => $r->str('id'), 'title' => $r->str('title'), 'slug' => $r->str('slug')];
        }, $rows));
    }
}
