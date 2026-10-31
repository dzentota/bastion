<?php
declare(strict_types=1);

namespace Bastion\Tests\Integration;

use Bastion\Content\Domain\{Entry, EntryType, Language, Slug, Title};
use Bastion\Content\Domain\Block\BlockList;
use Bastion\Content\Infrastructure\EntryRepository;
use Bastion\IdentityAccess\Domain\{NewPassword, Role, Username};
use Bastion\IdentityAccess\Infrastructure\AccountRepository;
use Bastion\Tests\Support\Database;
use ParagonIE\Halite\KeyFactory;
use ParagonIE\HiddenString\HiddenString;
use PHPUnit\Framework\TestCase;

final class RepositoriesTest extends TestCase
{
    public function testEntryLifecycle(): void
    {
        $repo = new EntryRepository(Database::memory());
        $e = Entry::draft(EntryType::Post, Language::fromNative('en'), Title::fromNative('Hello'), Slug::fromNative('hello'),
            BlockList::fromJson('[{"type":"paragraph","data":{"text":"Hi"}}]'), 'author');
        $repo->save($e);
        self::assertNull($repo->findPublishedBySlug(Language::fromNative('en'), Slug::fromNative('hello')));

        $e->publish(new \DateTimeImmutable());
        $repo->save($e);
        $found = $repo->findPublishedBySlug(Language::fromNative('en'), Slug::fromNative('hello'));
        self::assertNotNull($found);
        self::assertSame($e->blocks()->toJson(), $found->blocks()->toJson());
        self::assertTrue($repo->slugTaken(Language::fromNative('en'), Slug::fromNative('hello')));
        self::assertFalse($repo->slugTaken(Language::fromNative('en'), Slug::fromNative('hello'), $e->id));
    }

    public function testAccountsAndEncryptedTotp(): void
    {
        $db = Database::memory();
        $repo = new AccountRepository($db, KeyFactory::generateEncryptionKey());
        $u = Username::fromNative('owner');
        $acct = $repo->create($u, NewPassword::forUser('correct horse battery staple', $u), Role::Admin);

        $creds = $repo->fetchByUsername('owner');
        self::assertTrue(password_verify('correct horse battery staple', $creds['hash']));
        self::assertNull($repo->fetchByUsername("owner' OR 1=1 --"));

        $repo->saveTotpSecret($acct->id, new HiddenString('JBSWY3DPEHPK3PXP'));
        self::assertSame('JBSWY3DPEHPK3PXP', $repo->totpSecret($acct->id)->getString());
        $stored = $db->selectCell('SELECT totp_secret FROM ?_accounts');
        self::assertStringNotContainsString('JBSWY3DPEHPK3PXP', $stored, 'секрет хранится зашифрованным');
        self::assertTrue($repo->find($acct->id->toNative())->hasTotp);
    }
}
