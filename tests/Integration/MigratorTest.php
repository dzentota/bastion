<?php
declare(strict_types=1);

namespace Bastion\Tests\Integration;

use Bastion\Infrastructure\Database\Connection;
use Bastion\Infrastructure\Database\Migrations\{Catalog, DatabaseBackup, M0001Baseline, M0002EntryLanguages, Migration, Migrator};
use PHPUnit\Framework\TestCase;
use SecureDb\Db;

/** ADR-0018: версионированные миграции с контрольными суммами. */
final class MigratorTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/bastion-migrator-' . bin2hex(random_bytes(4));
        mkdir($this->dir);
    }

    public function testFreshDatabaseGetsEveryMigrationOnce(): void
    {
        $db = $this->db();
        $m = $this->migrator($db, Catalog::all());
        self::assertSame(self::ids(), $m->state()->pending);
        self::assertSame(self::ids(), $m->migrate(null, 'test'));
        self::assertTrue($m->state()->isCurrent());
        self::assertSame([], $m->migrate(null, 'test'), 'повторный запуск ничего не делает');
    }

    public function testSiteInstalledBeforeAdr0018KeepsItsData(): void
    {
        $db = $this->db();
        (new M0001Baseline())->apply($db, 'sqlite'); // старая установка: таблицы есть, учёта нет
        $db->insert('?_terms', ['kind' => 'tag', 'slug' => 'php']);

        $m = $this->migrator($db, Catalog::all());
        self::assertSame(self::ids(), $m->state()->pending);
        $m->migrate(null, 'test');
        self::assertSame('php', $db->selectCell('SELECT slug FROM ?_terms'));
    }

    public function testEntryLanguagesMigrationKeepsExistingEntriesInTheDefaultLanguage(): void
    {
        $db = $this->db();
        $this->migrator($db, [new M0001Baseline()])->migrate(null, 'test');
        $db->insert('?_entries', ['id' => 'e1', 'type' => 'post', 'title' => 'Старый', 'slug' => 'old', 'blocks' => '[]',
            'status' => 'published', 'author_id' => 'a', 'published_at' => null, 'updated_at' => '2026-01-01T00:00:00+00:00']);

        $this->migrator($db, Catalog::all('ru'))->migrate(null, 'test');

        self::assertSame(['lang' => 'ru', 'translation_group' => 'e1', 'title' => 'Старый'], $db->selectRow('SELECT lang, translation_group, title FROM ?_entries'));
        // slug уникален в пределах языка, а не глобально
        $row = ['type' => 'post', 'title' => 'T', 'slug' => 'old', 'blocks' => '[]', 'status' => 'draft', 'author_id' => 'a', 'published_at' => null, 'updated_at' => 'x'];
        $db->insert('?_entries', ['id' => 'e2', 'lang' => 'en', 'translation_group' => 'e1'] + $row);
        $this->expectException(\Throwable::class);
        $db->insert('?_entries', ['id' => 'e3', 'lang' => 'en', 'translation_group' => 'e3'] + $row);
    }

    public function testDefaultLanguageDoesNotChangeTheChecksum(): void
    {
        self::assertSame(Migrator::checksum(new M0002EntryLanguages('en'), 'sqlite'), Migrator::checksum(new M0002EntryLanguages('ru'), 'sqlite'));
    }

    public function testNewMigrationRunsAfterBaselineAndCanAlterExistingTables(): void
    {
        $db = $this->db();
        $this->migrator($db, Catalog::all())->migrate(null, 'test');
        $m = $this->migrator($db, [...Catalog::all(), self::fake('0002_add_column', ['ALTER TABLE ?_terms ADD COLUMN note TEXT NULL'])]);
        self::assertSame(['0002_add_column'], $m->state()->pending);
        $m->migrate(null, 'test');
        $db->insert('?_terms', ['kind' => 'tag', 'slug' => 'x', 'note' => 'ok']);
        self::assertSame('ok', $db->selectCell('SELECT note FROM ?_terms'));
    }

    public function testFailedMigrationIsRolledBackAndNotRecorded(): void
    {
        $db = $this->db();
        $this->migrator($db, Catalog::all())->migrate(null, 'test');
        $m = $this->migrator($db, [...Catalog::all(), self::fake('0002_broken', ['CREATE TABLE ?_half (id INTEGER)', 'NOT SQL'])]);
        try {
            $m->migrate(null, 'test');
            self::fail('migration should fail');
        } catch (\Throwable) {
        }
        self::assertSame(['0002_broken'], $m->state()->pending);
        self::assertSame(0, (int) $db->selectCell("SELECT COUNT(*) FROM sqlite_master WHERE name = 'bst_half'"), 'DDL SQLite откатан транзакцией');
    }

    public function testBackupRunsOnlyWhenSomethingIsPending(): void
    {
        $db = $this->db();
        $m = $this->migrator($db, Catalog::all());
        $backups = 0;
        $m->migrate(null, 'test', null, function () use (&$backups): void { $backups++; });
        $m->migrate(null, 'test', null, function () use (&$backups): void { $backups++; });
        self::assertSame(1, $backups);

        $file = (new DatabaseBackup($db, 'sqlite', $this->dir . '/backups'))->create();
        self::assertSame('0600', substr(sprintf('%o', fileperms($file)), -4));
        self::assertSame('0001_baseline', Connection::sqlite($file)->selectCell('SELECT id FROM ?_schema_migrations'), 'копия — рабочая база');
    }

    public function testBrokenBackupAbortsBeforeAnyMigration(): void
    {
        $db = $this->db();
        $m = $this->migrator($db, Catalog::all());
        try {
            $m->migrate(null, 'test', null, static fn () => throw new \RuntimeException('disk full'));
            self::fail('should abort');
        } catch (\RuntimeException $e) {
            self::assertSame('disk full', $e->getMessage());
        }
        self::assertSame(self::ids(), $m->state()->pending);
    }

    /** @return list<string> */
    private static function ids(): array
    {
        return array_map(static fn (Migration $m) => $m->id(), Catalog::all());
    }

    private function db(): Db
    {
        return Connection::sqlite($this->dir . '/db.sqlite');
    }

    /** @param list<Migration> $list */
    private function migrator(Db $db, array $list): Migrator
    {
        return new Migrator($db, 'sqlite', $this->dir . '/migrate.lock', $list);
    }

    /** @param list<string> $sql */
    public static function fake(string $id, array $sql): Migration
    {
        return new class ($id, $sql) implements Migration {
            /** @param list<string> $sql */
            public function __construct(private readonly string $id, private readonly array $sql)
            {
            }

            public function id(): string
            {
                return $this->id;
            }

            public function statements(string $driver): array
            {
                return $this->sql;
            }

            public function apply(Db $db, string $driver): void
            {
                foreach ($this->sql as $q) {
                    $db->query($q);
                }
            }
        };
    }
}
