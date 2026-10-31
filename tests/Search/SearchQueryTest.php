<?php
declare(strict_types=1);

namespace Bastion\Tests\Search;

use Bastion\Search\Domain\SearchQuery;
use PHPUnit\Framework\TestCase;

/** Abuser stories: search-query-injection, search-dos. */
final class SearchQueryTest extends TestCase
{
    public function testOperatorsNeverReachTheEngine(): void
    {
        $q = SearchQuery::parse('title:admin OR "x" NEAR(a b) -secret ^start * {col}:x Установка');
        self::assertNotNull($q);
        self::assertSame(['title', 'admin', 'or', 'x', 'near', 'a', 'b', 'secret'], $q->terms, 'операторы стали словами, лишние слова отброшены');
        self::assertSame('"title"* AND "admin"* AND "or" AND "x" AND "near"* AND "a" AND "b" AND "secret"*', $q->fts5());
        self::assertSame('+title* +admin* +"or" +"x" +near* +"a" +"b" +secret*', $q->booleanMode());
        self::assertSame(['установка'], SearchQuery::parse('УСТАНОВКА')?->terms);
    }

    public function testBounds(): void
    {
        self::assertNull(SearchQuery::parse(str_repeat('a', SearchQuery::MAX_BYTES + 1)));
        self::assertNull(SearchQuery::parse('" * - ( )'));
        self::assertNull(SearchQuery::parse(['array']));
        self::assertNull(SearchQuery::parse("\xff\xfe"));
        self::assertSame([], SearchQuery::parse(str_repeat('a', SearchQuery::MAX_TERM + 1) . ' ok')?->terms === ['ok'] ? [] : ['fail']);
        self::assertCount(SearchQuery::MAX_TERMS, SearchQuery::parse(implode(' ', range(1, 30)))?->terms ?? []);
        self::assertSame('"ab"', SearchQuery::parse('ab')?->fts5(), 'короткие слова — без префиксного поиска');
    }
}
