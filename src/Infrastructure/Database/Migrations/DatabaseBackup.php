<?php
declare(strict_types=1);

namespace Bastion\Infrastructure\Database\Migrations;

use Bastion\Infrastructure\Database\Tables;
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};
use SecureDb\Db;

/**
 * Резервная копия перед миграцией: откат — восстановление из неё (down-миграций нет).
 * Каталог var/backups вне document root, файлы 0600.
 */
#[AssetId('schema-migrator')]
#[AbuserStory('migration-data-loss')]
#[Mitigation(cwe: 'CWE-1188', description: 'Full database backup is taken before the first pending migration runs; the update aborts if the backup fails')]
final class DatabaseBackup
{
    public function __construct(private readonly Db $db, private readonly string $driver, private readonly string $dir)
    {
    }

    /** @return string путь к копии */
    public function create(): string
    {
        if (!is_dir($this->dir) && !mkdir($this->dir, 0700, true) && !is_dir($this->dir)) {
            throw new \RuntimeException('Cannot create backup directory');
        }
        $base = $this->dir . '/db-' . gmdate('Ymd-His') . '-' . bin2hex(random_bytes(3));
        $pdo = $this->db->getPdo();
        if ($this->driver === 'sqlite') {
            $file = $base . '.sqlite';
            $pdo->exec('VACUUM INTO ' . $pdo->quote($file)); // согласованный снимок, без копирования WAL вручную
        } else {
            $file = $base . '.json';
            $out = fopen($file, 'x');
            if ($out === false) {
                throw new \RuntimeException('Cannot write backup');
            }
            $tables = $pdo->query('SHOW TABLES LIKE ' . $pdo->quote(str_replace('_', '\\_', Tables::PREFIX) . '%'));
            fwrite($out, "{\n");
            foreach ($tables === false ? [] : $tables->fetchAll(\PDO::FETCH_COLUMN) as $i => $table) {
                $table = is_string($table) ? $table : '';
                $rows = $pdo->query('SELECT * FROM `' . str_replace('`', '', $table) . '`');
                fwrite($out, ($i > 0 ? ",\n" : '') . json_encode($table) . ': ' . json_encode($rows === false ? [] : $rows->fetchAll(\PDO::FETCH_ASSOC), JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE));
            }
            fwrite($out, "\n}\n");
            fclose($out);
        }
        if (!is_file($file) || filesize($file) === 0) {
            throw new \RuntimeException('Backup is empty');
        }
        chmod($file, 0600);
        return $file;
    }
}
