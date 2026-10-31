<?php
declare(strict_types=1);

namespace Bastion\Tests\Content;

use Bastion\Content\Application\PreviewTokens;
use Bastion\Content\Domain\{EntryId, PreviewToken};
use Bastion\Tests\Support\FrozenClock;
use PHPUnit\Framework\TestCase;

/** Abuser story: preview-token-abuse. */
final class PreviewTokensTest extends TestCase
{
    public function testTokenIsBoundToAccountSignedAndShortLived(): void
    {
        $clock = new FrozenClock(new \DateTimeImmutable('2026-10-31 12:00:00'));
        $tokens = new PreviewTokens(str_repeat('k', 32), $clock);
        $rev = EntryId::generate();
        $t = $tokens->issue($rev, 'alice');

        self::assertTrue($rev->isSame($tokens->verify($t, 'alice') ?? EntryId::generate()));
        self::assertNull($tokens->verify($t, 'bob'), 'чужой токен');
        self::assertNull((new PreviewTokens(str_repeat('x', 32), $clock))->verify($t, 'alice'), 'другой ключ');

        $sig = substr($t->toNative(), -43);
        $forged = rtrim(strtr(base64_encode(json_encode([$rev->toNative(), 'alice', 9999999999])), '+/', '-_'), '=');
        self::assertNull($tokens->verify(PreviewToken::fromNative($forged . $sig), 'alice'), 'изменённый срок');

        $clock->advance(PreviewTokens::TTL + 1);
        self::assertNull($tokens->verify($t, 'alice'), 'истёк');
    }
}
