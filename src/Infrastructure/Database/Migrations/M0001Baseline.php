<?php
declare(strict_types=1);

namespace Bastion\Infrastructure\Database\Migrations;

use Bastion\Infrastructure\Database\{Schema, Tables};
use Dzentota\Session\Storage\DatabaseStorage;
use SecureDb\Db;

/**
 * Схема MVP. Операторы идемпотентны, поэтому сайты, установленные до ADR-0018,
 * применяют её поверх существующих таблиц без потери данных.
 * Schema::statements() заморожен: новые изменения — только новыми миграциями.
 */
final class M0001Baseline implements Migration
{
    public function id(): string
    {
        return '0001_baseline';
    }

    public function statements(string $driver): array
    {
        return Schema::statements($driver);
    }

    public function apply(Db $db, string $driver): void
    {
        foreach ($this->statements($driver) as $sql) {
            $db->query($sql);
        }
        $sessions = new DatabaseStorage($db->getPdo(), Tables::SESSIONS);
        if (!$sessions->createTable()) {
            throw new \RuntimeException('Cannot create sessions table', 0, $sessions->getLastError());
        }
    }
}
