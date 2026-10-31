<?php
declare(strict_types=1);

namespace Bastion\Tests\Integration;

use Bastion\Infrastructure\Database\{Connection, Schema};
use PHPUnit\Framework\TestCase;

/** Схема догоняется на рабочей базе: повторный migrate не падает и не трогает данные. */
final class SchemaMigrateTest extends TestCase
{
    public function testMigrateIsIdempotentAndAddsMissingTables(): void
    {
        $file = sys_get_temp_dir() . '/bastion-migrate-' . bin2hex(random_bytes(4)) . '.sqlite';
        $db = Connection::sqlite($file);
        Schema::migrate($db, 'sqlite');
        $db->insert('?_terms', ['kind' => 'tag', 'slug' => 'php']);
        $db->query('DROP TABLE ?_ledger'); // сайт, установленный до появления журнала

        Schema::migrate($db, 'sqlite');

        self::assertSame(0, (int) $db->selectCell('SELECT COUNT(*) FROM ?_ledger'));
        self::assertSame('php', $db->selectCell('SELECT slug FROM ?_terms'));
        foreach (Schema::statements('mysql') as $sql) {
            self::assertMatchesRegularExpression('/^\s*CREATE TABLE IF NOT EXISTS/', $sql, 'MySQL DDL тоже идемпотентен');
        }
        unlink($file);
    }

    public function testSchemaIsMigratedAutomaticallyWhenCodeVersionChanges(): void
    {
        $dir = sys_get_temp_dir() . '/bastion-auto-' . bin2hex(random_bytes(4));
        mkdir($dir);
        $db = Connection::sqlite($dir . '/db.sqlite');
        Schema::migrate($db, 'sqlite', $dir . '/schema.version');
        self::assertSame(Schema::version('sqlite') . "\n", file_get_contents($dir . '/schema.version'));

        // сайт на старой версии: таблицы нет, записанная версия устарела
        $db->query('DROP TABLE ?_menu');
        file_put_contents($dir . '/schema.version', "old\n");
        Schema::ensureCurrent($db, 'sqlite', $dir . '/schema.version');
        self::assertSame(0, (int) $db->selectCell('SELECT COUNT(*) FROM ?_menu'));
        self::assertSame(Schema::version('sqlite') . "\n", file_get_contents($dir . '/schema.version'));

        // версия совпадает — миграция не запускается
        $db->query('DROP TABLE ?_menu');
        Schema::ensureCurrent($db, 'sqlite', $dir . '/schema.version');
        $this->expectException(\SecureDb\Exception\SecureDbException::class);
        $db->selectCell('SELECT COUNT(*) FROM ?_menu');
    }
}
