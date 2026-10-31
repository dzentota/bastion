<?php
declare(strict_types=1);

namespace Bastion\Infrastructure\Database;

use Dzentota\Session\Storage\DatabaseStorage;
use SecureDb\Db;

/**
 * Схема БД. DDL совместим с SQLite и MySQL (только переносимые типы).
 * Все операторы идемпотентны: migrate() безопасно запускать на рабочей базе (bin/bastion migrate)
 * — так новые таблицы появляются на уже установленных сайтах. Изменение существующих колонок
 * этим путём не поддерживается.
 */
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
                email {$key} NULL UNIQUE,
                credentials_version INTEGER NOT NULL DEFAULT 0,
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
            "CREATE TABLE IF NOT EXISTS ?_password_resets (
                selector CHAR(32) PRIMARY KEY,
                verifier_hash CHAR(64) NOT NULL,
                account_id {$key} NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                used INTEGER NOT NULL DEFAULT 0
            ){$suffix}",
            "CREATE TABLE IF NOT EXISTS ?_extensions (
                name VARCHAR(80) PRIMARY KEY,
                manifest {$text} NOT NULL,
                files {$text} NOT NULL,
                granted {$text} NOT NULL,
                enabled INTEGER NOT NULL,
                mac CHAR(64) NOT NULL
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
            "CREATE TABLE IF NOT EXISTS ?_comments (
                id VARCHAR(32) PRIMARY KEY,
                entry_id VARCHAR(36) NOT NULL,
                author VARCHAR(255) NOT NULL,
                body {$text} NOT NULL,
                status VARCHAR(16) NOT NULL,
                fingerprint VARCHAR(32) NOT NULL,
                created_at INTEGER NOT NULL
            ){$suffix}",
            "CREATE TABLE IF NOT EXISTS ?_terms (
                kind VARCHAR(16) NOT NULL,
                slug VARCHAR(96) NOT NULL,
                PRIMARY KEY (kind, slug)
            ){$suffix}",
            "CREATE TABLE IF NOT EXISTS ?_entry_terms (
                entry_id VARCHAR(36) NOT NULL,
                kind VARCHAR(16) NOT NULL,
                slug VARCHAR(96) NOT NULL,
                PRIMARY KEY (entry_id, kind, slug)" . ($driver === 'mysql' ? ",
                INDEX entry_terms_by_term (kind, slug, entry_id)" : '') . "
            ){$suffix}",
            // листинг термина ищет по (kind, slug) — без полного сканирования; в MySQL индекс объявлен в таблице
            ...($driver === 'mysql' ? [] : ["CREATE INDEX IF NOT EXISTS ?_entry_terms_by_term ON ?_entry_terms (kind, slug, entry_id)"]),
            "CREATE TABLE IF NOT EXISTS ?_menu (
                entry_id VARCHAR(36) PRIMARY KEY,
                position INTEGER NOT NULL
            ){$suffix}",
            "CREATE TABLE IF NOT EXISTS ?_ledger (
                seq INTEGER PRIMARY KEY,
                hash VARCHAR(64) NOT NULL,
                contents {$text} NOT NULL,
                mac CHAR(64) NOT NULL
            ){$suffix}",
            "CREATE TABLE IF NOT EXISTS ?_audit (
                seq INTEGER PRIMARY KEY,
                at INTEGER NOT NULL,
                action VARCHAR(32) NOT NULL,
                actor VARCHAR(64) NULL,
                subject VARCHAR(64) NULL,
                ip VARCHAR(64) NOT NULL,
                mac CHAR(64) NOT NULL
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
