<?php
declare(strict_types=1);

namespace Bastion\Updates\Infrastructure;

use Bastion\Infrastructure\Database\Row;
use Bastion\Updates\Application\ChronicleFeed;
use Bastion\Updates\Domain\InvalidRecord;
use SecureDb\Db;

/**
 * Локальная реплика журнала Chronicle. Цепочка хэшей пересчитывается при каждом чтении,
 * а каждая строка подписана HMAC ключом вне БД: доступ к БД не позволяет вписать «релиз».
 */
final class LedgerStore
{
    public function __construct(private readonly Db $db, #[\SensitiveParameter] private readonly string $key)
    {
    }

    /**
     * @return list<string> содержимое записей по порядку
     * @throws InvalidRecord
     */
    public function contents(): array
    {
        $out = [];
        $prev = '';
        foreach ($this->db->select('SELECT * FROM ?_ledger ORDER BY seq') as $i => $raw) {
            $r = Row::of($raw);
            $contents = $r->str('contents');
            if ($r->int('seq') !== $i + 1 || !hash_equals(ChronicleFeed::hash($prev, $contents), $r->str('hash'))
                || !hash_equals($this->mac($r->int('seq'), $r->str('hash')), $r->str('mac'))) {
                throw new InvalidRecord('Local update ledger is corrupted or tampered with');
            }
            $out[] = $contents;
            $prev = $r->str('hash');
        }
        return $out;
    }

    public function head(): string
    {
        $h = $this->db->selectCell('SELECT hash FROM ?_ledger ORDER BY seq DESC LIMIT 1');
        return is_string($h) ? $h : '';
    }

    /** @param list<array{hash: string, contents: string}> $entries уже проверены ChronicleFeed */
    public function append(array $entries): void
    {
        $this->db->tryFlatTransaction(function (Db $db) use ($entries): void {
            $n = $db->selectCell('SELECT COUNT(*) FROM ?_ledger');
            $seq = is_numeric($n) ? (int) $n : 0;
            foreach ($entries as $e) {
                $seq++;
                $db->insert('?_ledger', ['seq' => $seq, 'hash' => $e['hash'], 'contents' => $e['contents'], 'mac' => $this->mac($seq, $e['hash'])]);
            }
        });
    }

    private function mac(int $seq, string $hash): string
    {
        return hash_hmac('sha256', $seq . '|' . $hash, $this->key);
    }
}
