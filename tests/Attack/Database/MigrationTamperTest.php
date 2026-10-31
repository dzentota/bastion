<?php
declare(strict_types=1);

namespace Bastion\Tests\Attack\Database;

use Bastion\Infrastructure\Database\Connection;
use Bastion\Infrastructure\Database\Migrations\{Catalog, Migrator, TamperedMigrations};
use Bastion\Tests\Integration\MigratorTest;
use PHPUnit\Framework\TestCase;

/** Abuser stories: tamper-applied-migration, plant-migration. */
final class MigrationTamperTest extends TestCase
{
    public function testChangedAppliedMigrationBlocksUpdates(): void
    {
        $dir = sys_get_temp_dir() . '/bastion-tamper-' . bin2hex(random_bytes(4));
        mkdir($dir);
        $db = Connection::sqlite($dir . '/db.sqlite');
        (new Migrator($db, 'sqlite', $dir . '/l', [...Catalog::all(), MigratorTest::fake('0002_x', ['CREATE TABLE ?_x (id INTEGER)'])]))->migrate(null, 't');

        // тот же id, другой DDL: подменённый релиз или переписанная история
        $m = new Migrator($db, 'sqlite', $dir . '/l', [...Catalog::all(), MigratorTest::fake('0002_x', ['DROP TABLE ?_accounts']),
            MigratorTest::fake('0003_y', ['CREATE TABLE ?_y (id INTEGER)'])]);
        self::assertSame(['0002_x'], $m->state()->tampered);
        $this->expectException(TamperedMigrations::class);
        try {
            $m->migrate(null, 't');
        } finally {
            self::assertSame(0, (int) $db->selectCell("SELECT COUNT(*) FROM sqlite_master WHERE name = 'bst_y'"), 'ни одна миграция не применена');
        }
    }

    public function testRecordUnknownToTheCodeIsReportedAsTampered(): void
    {
        $dir = sys_get_temp_dir() . '/bastion-tamper-' . bin2hex(random_bytes(4));
        mkdir($dir);
        $db = Connection::sqlite($dir . '/db.sqlite');
        $m = new Migrator($db, 'sqlite', $dir . '/l', Catalog::all());
        $m->migrate(null, 't');
        $db->insert('?_schema_migrations', ['id' => '9999_forged', 'checksum' => str_repeat('0', 64), 'applied_at' => 0]);
        self::assertSame(['9999_forged'], $m->state()->tampered);
    }

    public function testFilesDroppedNextToTheCodeAreNotMigrations(): void
    {
        $src = dirname(__DIR__, 3) . '/src/Infrastructure/Database/Migrations/Catalog.php';
        self::assertDoesNotMatchRegularExpression('/\b(glob|scandir|opendir|DirectoryIterator|include|require)\b/', (string) file_get_contents($src));
    }
}
