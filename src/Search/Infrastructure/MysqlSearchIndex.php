<?php
declare(strict_types=1);

namespace Bastion\Search\Infrastructure;

use Bastion\Content\Domain\{Entry, EntryId, EntryStatus, Language};
use Bastion\Infrastructure\Database\Row;
use Bastion\Search\Domain\{SearchHit, SearchIndex, SearchQuery, SearchText, Snippet};
use SecureDb\Db;

/** MySQL/MariaDB FULLTEXT (InnoDB, BOOLEAN MODE). Отрывок строится в PHP. */
final class MysqlSearchIndex implements SearchIndex
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
            'SELECT s.entry_id, e.title, e.slug, s.body, MATCH(s.title, s.body) AGAINST (? IN BOOLEAN MODE) AS score
             FROM ?_search s JOIN ?_entries e ON e.id = s.entry_id
             WHERE MATCH(s.title, s.body) AGAINST (? IN BOOLEAN MODE) AND s.lang = ? AND e.status = ?
             ORDER BY score DESC LIMIT ?',
            $q = $query->booleanMode(), $q, $lang->toNative(), EntryStatus::Published->value, self::PAGE,
        );
        return array_values(array_map(static function (mixed $raw) use ($query): SearchHit {
            $r = Row::of($raw);
            return new SearchHit($r->str('entry_id'), $r->str('title'), $r->str('slug'), Snippet::make($r->str('body'), $query->terms));
        }, $rows));
    }
}
