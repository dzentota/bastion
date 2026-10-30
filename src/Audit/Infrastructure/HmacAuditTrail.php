<?php
declare(strict_types=1);

namespace Bastion\Audit\Infrastructure;

use Bastion\Audit\Domain\{AuditAction, AuditEntry, AuditTrail, Verification};
use Bastion\Infrastructure\Database\Row;
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};
use Psr\Clock\ClockInterface;
use SecureDb\Db;

/**
 * Журнал аудита — HMAC-цепочка: mac[n] = HMAC(key, mac[n-1] || canonical(entry[n])).
 * Ключ хранится вне БД (var/keys), поэтому с доступом только к БД нельзя ни подделать,
 * ни изменить, ни переставить записи. Последний seq и mac дублируются в файл-якорь
 * вне БД — так обнаруживается и удаление хвоста. Запись сериализуется flock'ом на якоре.
 */
#[AssetId('bastion-app')]
#[AbuserStory('audit-repudiation')]
#[Mitigation(cwe: 'CWE-778', description: 'Logins, logouts, 2FA enrolment, entry create/update/publish, uploads, moderation, AppSensor responses and emergency unlocks are recorded with actor, subject and IP')]
#[AbuserStory('audit-tamper')]
#[Mitigation(cwe: 'CWE-354', description: 'Keyed HMAC chain over contiguous sequence numbers (key outside DB) plus an out-of-DB head anchor detects edits, deletions, reordering and truncation')]
#[Mitigation(cwe: 'CWE-117', description: 'Entries are structured: closed AuditAction enum, validated identifiers, canonical JSON for MAC; free text never logged; output escaped')]
final class HmacAuditTrail implements AuditTrail
{
    private const SUBJECT = '/^[A-Za-z0-9:_.-]{1,64}$/';

    public function __construct(
        private readonly Db $db,
        #[\SensitiveParameter] private readonly string $key,
        private readonly string $anchorFile,
        private readonly ClockInterface $clock,
    ) {
        if (strlen($key) < 32) {
            throw new \InvalidArgumentException('Audit key must be at least 32 bytes');
        }
    }

    public function record(AuditAction $action, ?string $actor, ?string $subject, string $ip): void
    {
        foreach ([$actor, $subject] as $v) {
            if ($v !== null && !preg_match(self::SUBJECT, $v)) {
                throw new \InvalidArgumentException('Audit identifiers must be plain ids');
            }
        }
        if (filter_var($ip, FILTER_VALIDATE_IP) === false && $ip !== 'cli') {
            $ip = 'unknown';
        }

        $lock = fopen($this->anchorFile . '.lock', 'c');
        if ($lock === false || !flock($lock, LOCK_EX)) {
            throw new \RuntimeException('Cannot lock audit trail');
        }
        try {
            $last = $this->db->selectRow('SELECT seq, mac FROM ?_audit ORDER BY seq DESC LIMIT 1');
            [$seq, $prev] = $last ? [Row::of($last)->int('seq') + 1, Row::of($last)->str('mac')] : [1, str_repeat('0', 64)];
            $draft = new AuditEntry($seq, $this->clock->now()->getTimestamp(), $action, $actor, $subject, $ip, '');
            $mac = hash_hmac('sha256', $prev . $draft->canonical(), $this->key);
            $this->db->insert('?_audit', [
                'seq' => $seq, 'at' => $draft->at, 'action' => $action->value,
                'actor' => $actor, 'subject' => $subject, 'ip' => $ip, 'mac' => $mac,
            ]);
            $this->writeAnchor($seq, $mac);
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    /** @return list<AuditEntry> */
    public function latest(int $limit): array
    {
        $rows = $this->db->select('SELECT * FROM ?_audit ORDER BY seq DESC LIMIT ?', max(1, min($limit, 1000)));
        return array_values(array_map(fn (mixed $r) => $this->hydrate(Row::of($r)), $rows));
    }

    public function verify(): Verification
    {
        $prev = str_repeat('0', 64);
        $expected = 1;
        $count = 0;
        foreach ($this->db->select('SELECT * FROM ?_audit ORDER BY seq ASC') as $raw) {
            try {
                $e = $this->hydrate(Row::of($raw));
            } catch (\Throwable) {
                return Verification::broken($count, $expected, 'Malformed entry');
            }
            if ($e->seq !== $expected) {
                return Verification::broken($count, $expected, "Entry #{$expected} is missing");
            }
            if (!hash_equals(hash_hmac('sha256', $prev . $e->canonical(), $this->key), $e->mac)) {
                return Verification::broken($count, $e->seq, "Entry #{$e->seq} was modified");
            }
            $prev = $e->mac;
            $expected++;
            $count++;
        }
        $anchor = $this->readAnchor();
        if ($anchor === null) {
            return $count === 0 ? Verification::ok(0) : Verification::broken($count, $count, 'Anchor file is missing');
        }
        if ($anchor['seq'] !== $count || !hash_equals($anchor['mac'], $prev)) {
            return Verification::broken($count, $count + 1, "Entries after #{$count} were removed (anchor says #{$anchor['seq']})");
        }
        return Verification::ok($count);
    }

    private function hydrate(Row $r): AuditEntry
    {
        $actor = $r->nullableStr('actor');
        $subject = $r->nullableStr('subject');
        return new AuditEntry($r->int('seq'), $r->int('at'), AuditAction::from($r->str('action')), $actor, $subject, $r->str('ip'), $r->str('mac'));
    }

    private function writeAnchor(int $seq, string $mac): void
    {
        $payload = $seq . ':' . $mac;
        $line = $payload . ':' . hash_hmac('sha256', 'anchor:' . $payload, $this->key) . "\n";
        $tmp = $this->anchorFile . '.' . bin2hex(random_bytes(6));
        if (file_put_contents($tmp, $line) === false) {
            throw new \RuntimeException('Cannot write audit anchor');
        }
        chmod($tmp, 0600);
        rename($tmp, $this->anchorFile);
    }

    /** @return array{seq: int, mac: string}|null */
    private function readAnchor(): ?array
    {
        $raw = is_file($this->anchorFile) ? trim((string) file_get_contents($this->anchorFile)) : '';
        if (!preg_match('/^(\d+):([0-9a-f]{64}):([0-9a-f]{64})$/', $raw, $m)) {
            return null;
        }
        if (!hash_equals(hash_hmac('sha256', 'anchor:' . $m[1] . ':' . $m[2], $this->key), $m[3])) {
            return null;
        }
        return ['seq' => (int) $m[1], 'mac' => $m[2]];
    }
}
