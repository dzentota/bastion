<?php
declare(strict_types=1);

namespace Bastion\Infrastructure\Database;

use SecureDb\Db;

final class Connection
{
    public static function sqlite(string $path): Db
    {
        $pdo = new \PDO('sqlite:' . $path, null, null, [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION, \PDO::ATTR_TIMEOUT => 5]);
        $pdo->exec('PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON;');
        // WAL сохраняется в файле. Переключение режима не ждёт busy_timeout, поэтому
        // при одновременном открытии новой базы несколькими процессами — короткий повтор.
        for ($try = 0; self::journalMode($pdo) !== 'wal'; $try++) {
            try {
                $pdo->exec('PRAGMA journal_mode = WAL');
            } catch (\PDOException $e) {
                if ($try >= 50) {
                    throw $e;
                }
                usleep(20000);
            }
        }
        return self::wrap($pdo, 'sqlite');
    }

    private static function journalMode(\PDO $pdo): string
    {
        $mode = $pdo->query('PRAGMA journal_mode');
        $value = $mode === false ? '' : $mode->fetchColumn();
        return is_string($value) ? strtolower($value) : '';
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
