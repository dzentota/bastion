<?php
declare(strict_types=1);

namespace Bastion\Tests\Content;

use Bastion\Content\Domain\{EntryId, Revision, RevisionDiff, Slug, Title};
use Bastion\Content\Domain\Block\BlockList;
use PHPUnit\Framework\TestCase;

/** Abuser story: diff-dos. */
final class RevisionDiffTest extends TestCase
{
    public function testLineDiff(): void
    {
        $d = RevisionDiff::between($this->rev("a\nb\nc"), $this->rev("a\nx\nc"));
        self::assertSame([
            ['op' => 'same', 'text' => '# T'], ['op' => 'same', 'text' => '/t'],
            ['op' => 'same', 'text' => 'paragraph: a'], ['op' => 'del', 'text' => 'paragraph: b'],
            ['op' => 'add', 'text' => 'paragraph: x'], ['op' => 'same', 'text' => 'paragraph: c'],
        ], $d->ops);
        self::assertFalse(RevisionDiff::between($this->rev('a'), $this->rev('a'))->changed());
    }

    public function testHugeRevisionsAreNotDiffed(): void
    {
        $big = implode("\n", array_map('strval', range(1, RevisionDiff::MAX_LINES + 10)));
        $start = microtime(true);
        $d = RevisionDiff::between($this->rev($big), $this->rev($big . "\nmore"));
        self::assertTrue($d->tooLarge);
        self::assertLessThan(0.5, microtime(true) - $start);
    }

    private function rev(string $text): Revision
    {
        $blocks = BlockList::fromJson(json_encode([['type' => 'paragraph', 'data' => ['text' => $text]]], JSON_THROW_ON_ERROR));
        return new Revision(EntryId::generate(), EntryId::generate(), 1, Title::fromNative('T'), Slug::fromNative('t'), $blocks, 'a', new \DateTimeImmutable());
    }
}
