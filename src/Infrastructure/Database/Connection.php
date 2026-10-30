<?php
declare(strict_types=1);

namespace Bastion\Infrastructure\Database;

use SecureDb\Db;

final class Connection
{
    public static function sqlite(string $path): Db
    {
        $pdo = new \PDO('sqlite:' . $path, null, null, [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION]);
        $pdo->exec('PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;');
        return self::wrap($pdo, 'sqlite');
    }

    public static function mysql(string $host, int $port, string $database, string $user, #[\SensitiveParameter] string $password): Db
    {
        $pdo = new \PDO(
            sprintf('mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4', $host, $port, $database),
            $user,
            $password,
            [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION, \PDO::ATTR_EMULATE_PREPARES => false],
        );
        return self::wrap($pdo, 'mysql');
    }

    public static function wrap(\PDO $pdo, string $driver): Db
    {
        $db = Db::wrap($pdo, $driver);
        $db->setIdentifierPrefix(Tables::PREFIX);
        return $db;
    }
}
