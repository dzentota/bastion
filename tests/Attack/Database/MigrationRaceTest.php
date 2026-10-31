<?php
declare(strict_types=1);

namespace Bastion\Tests\Attack\Database;

use Bastion\Infrastructure\Database\Connection;
use Bastion\Infrastructure\Database\Migrations\Catalog;
use PHPUnit\Framework\TestCase;

/** Abuser story: migration-race — параллельные процессы применяют миграцию ровно один раз. */
final class MigrationRaceTest extends TestCase
{
    public function testConcurrentRunsApplyEachMigrationOnce(): void
    {
        $dir = sys_get_temp_dir() . '/bastion-race-' . bin2hex(random_bytes(4));
        mkdir($dir);
        $autoload = dirname(__DIR__, 3) . '/vendor/autoload.php';
        // медленная резервная копия держит блокировку, пока стартуют остальные
        $code = sprintf(<<<'PHP'
            require %s;
            $db = Bastion\Infrastructure\Database\Connection::sqlite(%s);
            $m = new Bastion\Infrastructure\Database\Migrations\Migrator($db, 'sqlite', %s, Bastion\Infrastructure\Database\Migrations\Catalog::all());
            echo count($m->migrate(null, 'race', null, static fn () => usleep(300000)));
            PHP, var_export($autoload, true), var_export($dir . '/db.sqlite', true), var_export($dir . '/migrate.lock', true));

        $procs = [];
        for ($i = 0; $i < 4; $i++) {
            $procs[] = proc_open([PHP_BINARY, '-r', $code], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes[$i]);
        }
        $applied = $winners = 0;
        foreach ($procs as $i => $p) {
            $out = stream_get_contents($pipes[$i][1]);
            $err = stream_get_contents($pipes[$i][2]);
            self::assertSame(0, proc_close($p), (string) $err);
            $applied += (int) $out;
            $winners += (int) $out > 0 ? 1 : 0;
        }
        self::assertSame(1, $winners, 'миграции применил только один процесс');
        self::assertSame(count(Catalog::all()), $applied);
        self::assertSame(count(Catalog::all()), (int) Connection::sqlite($dir . '/db.sqlite')->selectCell('SELECT COUNT(*) FROM ?_schema_migrations'));
    }
}
