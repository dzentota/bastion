<?php
declare(strict_types=1);

namespace Bastion\Search\Infrastructure;

use Bastion\Content\Domain\{Entry, EntryId, EntryStatus, Language};
use Bastion\Infrastructure\Database\Row;
use Bastion\Search\Domain\{SearchHit, SearchIndex, SearchQuery, SearchText};
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};
use SecureDb\Db;

/** FTS5 (unicode61, без учёта регистра и диакритики). Заголовок весит больше текста. */
#[AssetId('bastion-app')]
#[AbuserStory('search-draft-leak')]
#[Mitigation(cwe: 'CWE-200', description: 'Only published entries are indexed (on publish), and every result is joined back to entries with status = published, so drafts and unpublished changes never appear')]
final class SqliteSearchIndex implements SearchIndex
{
    public function __construct(private readonly Db $db)
    {
    }

    public function index(Entry $entry): void
    {
        $this->remove($entry->id);
        if ($entry->isPublished()) {
            $this->db->insert('?_search', [
                'entry_id' => $entry->id->toNative(), 'lang' => $entry->lang->toNative(),
                'title' => $entry->title()->toNative(), 'body' => SearchText::of($entry->blocks()),
            ]);
        }
    }

    public function remove(EntryId $entry): void
    {
        $this->db->query('DELETE FROM ?_search WHERE entry_id = ?', $entry->toNative());
    }

    public function search(Language $lang, SearchQuery $query): array
    {
        $rows = $this->db->select(
            "SELECT s.entry_id, e.title, e.slug, snippet(?_search, 3, ?, ?, '…', 24) AS snippet
             FROM ?_search s JOIN ?_entries e ON e.id = s.entry_id
             WHERE ?_search MATCH ? AND s.lang = ? AND e.status = ?
             ORDER BY bm25(?_search, 0.0, 0.0, 5.0, 1.0) LIMIT ?",
            SearchHit::MARK_OPEN, SearchHit::MARK_CLOSE, $query->fts5(), $lang->toNative(), EntryStatus::Published->value, self::PAGE,
        );
        return array_values(array_map(static function (mixed $raw): SearchHit {
            $r = Row::of($raw);
            return new SearchHit($r->str('entry_id'), $r->str('title'), $r->str('slug'), $r->str('snippet'));
        }, $rows));
    }
}
