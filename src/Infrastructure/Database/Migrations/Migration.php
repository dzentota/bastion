<?php
declare(strict_types=1);

namespace Bastion\Infrastructure\Database\Migrations;

use SecureDb\Db;

/**
 * Одна версия схемы (ADR-0018). После выпуска миграция заморожена: контрольная сумма
 * её DDL хранится в ?_schema_migrations, и расхождение блокирует обновление.
 */
interface Migration
{
    /** Вида 0001_baseline: номер задаёт порядок. */
    public function id(): string;

    /** @return list<string> DDL для драйвера (sqlite|mysql); по нему считается контрольная сумма */
    public function statements(string $driver): array;

    /** Применение: по умолчанию statements(); дополнительные шаги — без влияния на сумму. */
    public function apply(Db $db, string $driver): void;
}
