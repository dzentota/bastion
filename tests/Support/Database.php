<?php
declare(strict_types=1);

namespace Bastion\Tests\Support;

use Bastion\Infrastructure\Database\{Connection, Schema};
use SecureDb\Db;

final class Database
{
    public static function memory(): Db
    {
        $db = Connection::wrap(new \PDO('sqlite::memory:', null, null, [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION]), 'sqlite');
        Schema::migrate($db, 'sqlite');
        return $db;
    }
}
