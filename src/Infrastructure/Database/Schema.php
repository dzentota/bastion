<?php
declare(strict_types=1);

namespace Bastion\Infrastructure\Database;

use Dzentota\Session\Storage\DatabaseStorage;
use SecureDb\Db;

/** Схема БД. DDL совместим с SQLite и MySQL (только переносимые типы). */
final class Schema
{
    /** @return list<string> */
    public static function statements(string $driver): array
    {
        $text = $driver === 'mysql' ? 'LONGTEXT' : 'TEXT';
        $key = $driver === 'mysql' ? 'VARCHAR(191)' : 'TEXT';
        $suffix = $driver === 'mysql' ? ' ENGINE=InnoDB DEFAULT CHARSET=utf8mb4' : '';
        return [
            "CREATE TABLE IF NOT EXISTS ?_accounts (
                id {$key} PRIMARY KEY,
                username {$key} NOT NULL UNIQUE,
                password_hash {$key} NOT NULL,
                role VARCHAR(16) NOT NULL,
                totp_secret {$text} NULL,
                totp_last_step INTEGER NOT NULL DEFAULT 0,
                created_at VARCHAR(32) NOT NULL
            ){$suffix}",
            "CREATE TABLE IF NOT EXISTS ?_entries (
                id {$key} PRIMARY KEY,
                type VARCHAR(16) NOT NULL,
                title {$text} NOT NULL,
                slug {$key} NOT NULL UNIQUE,
                blocks {$text} NOT NULL,
                status VARCHAR(16) NOT NULL,
                author_id {$key} NOT NULL,
                published_at VARCHAR(32) NULL,
                updated_at VARCHAR(32) NOT NULL
            ){$suffix}",
            "CREATE TABLE IF NOT EXISTS ?_security_events (
                id INTEGER PRIMARY KEY " . ($driver === 'mysql' ? 'AUTO_INCREMENT' : 'AUTOINCREMENT') . ",
                detection_point VARCHAR(16) NOT NULL,
                actor_key VARCHAR(128) NOT NULL,
                created_at INTEGER NOT NULL
            ){$suffix}",
            "CREATE TABLE IF NOT EXISTS ?_security_responses (
                actor_key VARCHAR(128) NOT NULL,
                response VARCHAR(32) NOT NULL,
                until_ts INTEGER NOT NULL,
                PRIMARY KEY (actor_key, response)
            ){$suffix}",
            "CREATE TABLE IF NOT EXISTS ?_media (
                id VARCHAR(32) PRIMARY KEY,
                kind VARCHAR(8) NOT NULL,
                name VARCHAR(255) NOT NULL,
                bytes INTEGER NOT NULL,
                width INTEGER NULL,
                height INTEGER NULL,
                uploaded_by {$key} NOT NULL,
                uploaded_at INTEGER NOT NULL
            ){$suffix}",
            "CREATE TABLE IF NOT EXISTS ?_audit (
                id INTEGER PRIMARY KEY " . ($driver === 'mysql' ? 'AUTO_INCREMENT' : 'AUTOINCREMENT') . ",
                actor_id {$key} NULL,
                action VARCHAR(64) NOT NULL,
                subject {$key} NULL,
                ip VARCHAR(64) NOT NULL,
                created_at VARCHAR(32) NOT NULL,
                prev_hash CHAR(64) NOT NULL,
                hash CHAR(64) NOT NULL
            ){$suffix}",
        ];
    }

    public static function migrate(Db $db, string $driver): void
    {
        foreach (self::statements($driver) as $sql) {
            $db->query($sql);
        }
        $sessions = new DatabaseStorage($db->getPdo(), Tables::SESSIONS);
        if (!$sessions->createTable()) {
            throw new \RuntimeException('Cannot create sessions table', 0, $sessions->getLastError());
        }
    }
}
