<?php
declare(strict_types=1);

namespace Bastion\Search\Domain;

use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};

/**
 * Поисковый запрос посетителя, разобранный в слова. Синтаксис движка (FTS5 MATCH, MySQL BOOLEAN
 * MODE) пользователю недоступен: каждое слово экранируется как фраза, операторы не передаются.
 */
#[AssetId('bastion-app')]
#[AbuserStory('search-query-injection')]
#[Mitigation(cwe: 'CWE-943', description: 'User input never reaches the full-text query syntax: it is split into at most 8 letter/digit words, each emitted as a quoted phrase; engine operators are dropped')]
#[AbuserStory('search-dos')]
#[Mitigation(cwe: 'CWE-400', description: 'Queries are bounded (200 bytes, 8 words, 40 characters per word, prefix matching only from 3 characters) and results are capped at 20 per page')]
final class SearchQuery
{
    public const MAX_BYTES = 200;
    public const MAX_TERMS = 8;
    public const MAX_TERM = 40;
    public const PREFIX_FROM = 3;

    /** @param non-empty-list<string> $terms в нижнем регистре */
    private function __construct(public readonly string $text, public readonly array $terms)
    {
    }

    public static function parse(mixed $raw): ?self
    {
        if (!is_string($raw) || strlen($raw) > self::MAX_BYTES || !mb_check_encoding($raw, 'UTF-8')) {
            return null;
        }
        preg_match_all('/[\p{L}\p{N}]+/u', $raw, $m);
        $terms = [];
        foreach ($m[0] as $word) {
            $word = mb_strtolower($word);
            if (mb_strlen($word) <= self::MAX_TERM && !in_array($word, $terms, true)) {
                $terms[] = $word;
            }
            if (count($terms) === self::MAX_TERMS) {
                break;
            }
        }
        return $terms === [] ? null : new self(trim(preg_replace('/\s+/u', ' ', $raw) ?? ''), $terms);
    }

    /** FTS5 MATCH: "слово"* AND "слово" … — кавычки внутри слов невозможны по построению. */
    public function fts5(): string
    {
        return implode(' AND ', array_map(static fn (string $t) => '"' . $t . '"' . (mb_strlen($t) >= self::PREFIX_FROM ? '*' : ''), $this->terms));
    }

    /** MySQL BOOLEAN MODE: +"слово" или +слово* (префикс), только буквы и цифры. */
    public function booleanMode(): string
    {
        return implode(' ', array_map(static fn (string $t) => mb_strlen($t) >= self::PREFIX_FROM ? '+' . $t . '*' : '+"' . $t . '"', $this->terms));
    }
}
