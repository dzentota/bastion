<?php
declare(strict_types=1);

namespace Bastion\Tests\Support;

use Bastion\Infrastructure\Database\Connection;
use Bastion\Infrastructure\Database\Migrations\{Catalog, Migrator};
use SecureDb\Db;

final class Database
{
    public static function memory(): Db
    {
        $db = Connection::wrap(new \PDO('sqlite::memory:', null, null, [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION]), 'sqlite');
        (new Migrator($db, 'sqlite', sys_get_temp_dir() . '/bastion-test-migrate.lock', Catalog::all()))->migrate(null, 'test');
        return $db;
    }
}
