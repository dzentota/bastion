<?php
declare(strict_types=1);

namespace Bastion\Infrastructure\Database\Migrations;

use Bastion\Audit\Domain\{AuditAction, AuditTrail};
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};
use SecureDb\Db;

/**
 * Применяет версионированные миграции (ADR-0018). Чтение состояния — только SELECT:
 * обычный запрос схему не меняет. Применение — явный шаг администратора или CLI.
 */
#[AssetId('schema-migrator')]
final class Migrator
{
    private const TABLE = '?_schema_migrations';

    /** @param list<Migration> $migrations */
    public function __construct(
        private readonly Db $db,
        private readonly string $driver,
        private readonly string $lockFile,
        private readonly array $migrations,
    ) {
    }

    public static function checksum(Migration $m, string $driver): string
    {
        return hash('sha256', implode("\n;\n", $m->statements($driver)));
    }

    #[AbuserStory('tamper-applied-migration')]
    #[Mitigation(cwe: 'CWE-354', description: 'Checksum of every applied migration is stored and compared with the code; any mismatch or unknown record blocks updates')]
    public function state(): MigrationState
    {
        try {
            $rows = $this->db->select('SELECT id, checksum FROM ' . self::TABLE);
        } catch (\Throwable) {
            $rows = []; // сайт до ADR-0018: таблицы учёта ещё нет
        }
        $applied = [];
        foreach ($rows as $row) {
            if (is_array($row) && is_string($row['id'] ?? null) && is_string($row['checksum'] ?? null)) {
                $applied[$row['id']] = $row['checksum'];
            }
        }
        $pending = $tampered = [];
        foreach ($this->migrations as $m) {
            if (!isset($applied[$m->id()])) {
                $pending[] = $m->id();
            } elseif (!hash_equals($applied[$m->id()], self::checksum($m, $this->driver))) {
                $tampered[] = $m->id();
            }
            unset($applied[$m->id()]);
        }
        return new MigrationState($pending, array_merge($tampered, array_keys($applied)));
    }

    /**
     * Применяет все ожидающие миграции под файловой блокировкой.
     * @param ?callable(): void $beforeFirst например, резервная копия; вызывается, только если есть что применять
     * @return list<string> применённые id
     */
    #[AbuserStory('migration-race')]
    #[Mitigation(cwe: 'CWE-362', description: 'Exclusive file lock; state re-read under the lock; each migration in its own transaction where the driver allows DDL in transactions')]
    public function migrate(?string $actor, string $ip, ?AuditTrail $audit = null, ?callable $beforeFirst = null): array
    {
        $lock = fopen($this->lockFile, 'c');
        if ($lock === false || !flock($lock, LOCK_EX)) {
            throw new \RuntimeException('Cannot lock schema migration');
        }
        try {
            $state = $this->state();
            if ($state->tampered !== []) {
                throw new TamperedMigrations($state->tampered);
            }
            if ($state->pending === []) {
                return [];
            }
            if ($beforeFirst !== null) {
                $beforeFirst();
            }
            $this->db->query('CREATE TABLE IF NOT EXISTS ' . self::TABLE . ' (
                id VARCHAR(64) PRIMARY KEY,
                checksum VARCHAR(64) NOT NULL,
                applied_at INTEGER NOT NULL,
                applied_by VARCHAR(64) NULL
            )' . ($this->driver === 'mysql' ? ' ENGINE=InnoDB DEFAULT CHARSET=utf8mb4' : ''));
            $done = [];
            foreach ($this->migrations as $m) {
                if (!in_array($m->id(), $state->pending, true)) {
                    continue;
                }
                $this->inTransaction(function () use ($m, $actor): void {
                    $m->apply($this->db, $this->driver);
                    $this->db->insert(self::TABLE, [
                        'id' => $m->id(), 'checksum' => self::checksum($m, $this->driver),
                        'applied_at' => time(), 'applied_by' => $actor,
                    ]);
                });
                $audit?->record(AuditAction::SchemaMigrated, $actor, $m->id(), $ip);
                $done[] = $m->id();
            }
            return $done;
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    private function inTransaction(callable $fn): void
    {
        // MySQL неявно коммитит DDL — транзакция там защищает только запись учёта.
        $pdo = $this->db->getPdo();
        $pdo->beginTransaction();
        try {
            $fn();
            if ($pdo->inTransaction()) {
                $pdo->commit();
            }
        } catch (\Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            throw $e;
        }
    }
}
