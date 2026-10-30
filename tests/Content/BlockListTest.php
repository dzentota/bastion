<?php
declare(strict_types=1);

namespace Bastion\Tests\Content;

use Bastion\Content\Domain\Block\{BlockList, InvalidBlock};
use Bastion\Content\Domain\{EntryId, Slug, Title};
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class BlockListTest extends TestCase
{
    public function testRoundTrip(): void
    {
        $json = '[{"type":"heading","data":{"level":2,"text":"Привет"}},{"type":"paragraph","data":{"text":"a\nb"}}]';
        self::assertSame($json, BlockList::fromJson($json)->toJson());
    }

    public static function invalid(): iterable
    {
        yield 'not json' => ['{'];
        yield 'object' => ['{"type":"paragraph"}'];
        yield 'unknown type' => ['[{"type":"html","data":{"html":"<b>"}}]'];
        yield 'missing data' => ['[{"type":"paragraph"}]'];
        yield 'empty text' => ['[{"type":"paragraph","data":{"text":""}}]'];
        yield 'h1' => ['[{"type":"heading","data":{"level":1,"text":"x"}}]'];
        yield 'level string' => ['[{"type":"heading","data":{"level":"2","text":"x"}}]'];
        yield 'too deep' => ['[{"type":"paragraph","data":{"text":{"a":{"b":1}}}}]'];
        yield 'bidi override' => ['[{"type":"paragraph","data":{"text":"a‮b"}}]'];
        yield 'null byte' => ['[{"type":"paragraph","data":{"text":"a\u0000b"}}]'];
    }

    #[DataProvider('invalid')]
    public function testRejectsInvalid(string $json): void
    {
        $this->expectException(InvalidBlock::class);
        BlockList::fromJson($json);
    }

    public function testPrimitives(): void
    {
        self::assertTrue(Slug::tryParse('hello-world'));
        self::assertFalse(Slug::tryParse('Hello'));
        self::assertFalse(Slug::tryParse('../x'));
        self::assertFalse(Slug::tryParse('a--b'));
        self::assertFalse(Title::tryParse("a\nb"));
        self::assertTrue(EntryId::tryParse(EntryId::generate()->toNative()));
    }
}
