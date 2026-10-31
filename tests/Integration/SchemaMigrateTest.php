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
}
