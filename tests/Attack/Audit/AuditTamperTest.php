<?php
declare(strict_types=1);

namespace Bastion\Tests\Attack\Audit;

use Bastion\Audit\Domain\AuditAction;
use Bastion\Audit\Infrastructure\HmacAuditTrail;
use Bastion\Tests\Support\{Database, FrozenClock};
use PHPUnit\Framework\TestCase;
use SecureDb\Db;

/** Abuser story: audit-tamper — нарушитель с доступом к БД, но без var/keys. */
final class AuditTamperTest extends TestCase
{
    private Db $db;
    private HmacAuditTrail $trail;
    private string $anchor;

    protected function setUp(): void
    {
        $this->db = Database::memory();
        $this->anchor = sys_get_temp_dir() . '/bastion-audit-' . bin2hex(random_bytes(4));
        $this->trail = new HmacAuditTrail($this->db, random_bytes(32), $this->anchor, new FrozenClock());
        foreach ([AuditAction::LoginSucceeded, AuditAction::EntryCreated, AuditAction::EntryPublished, AuditAction::Logout] as $i => $a) {
            $this->trail->record($a, 'acct' . $i, 'subject' . $i, '198.51.100.' . $i);
        }
    }

    public function testIntactTrailVerifies(): void
    {
        $v = $this->trail->verify();
        self::assertTrue($v->intact, $v->reason);
        self::assertSame(4, $v->entries);
    }

    public function testEditedEntryIsDetected(): void
    {
        $this->db->query("UPDATE ?_audit SET actor = 'someone-else' WHERE seq = 3");
        $v = $this->trail->verify();
        self::assertFalse($v->intact);
        self::assertSame(3, $v->brokenAt);
    }

    public function testDeletedMiddleEntryIsDetected(): void
    {
        $this->db->query('DELETE FROM ?_audit WHERE seq = 2');
        self::assertFalse($this->trail->verify()->intact);
    }

    public function testTruncatedTailIsDetectedByAnchor(): void
    {
        $this->db->query('DELETE FROM ?_audit WHERE seq = 4');
        $v = $this->trail->verify();
        self::assertFalse($v->intact);
        self::assertStringContainsString('removed', $v->reason);
    }

    public function testRecomputingMacWithoutKeyFails(): void
    {
        // Атакующий пересчитывает цепочку обычным SHA-256 (ключа у него нет).
        $rows = $this->db->select('SELECT * FROM ?_audit ORDER BY seq');
        $prev = str_repeat('0', 64);
        foreach ($rows as $r) {
            $actor = $r['seq'] === 3 ? 'forged' : $r['actor'];
            $mac = hash('sha256', $prev . json_encode([$r['seq'], $r['at'], $r['action'], $actor, $r['subject'], $r['ip']]));
            $this->db->query('UPDATE ?_audit SET actor = ?, mac = ? WHERE seq = ?', $actor, $mac, $r['seq']);
            $prev = $mac;
        }
        self::assertFalse($this->trail->verify()->intact);
    }

    public function testWipingEverythingIsDetected(): void
    {
        $this->db->query('DELETE FROM ?_audit');
        self::assertFalse($this->trail->verify()->intact);
    }

    public function testForgedAnchorIsRejected(): void
    {
        $this->db->query('DELETE FROM ?_audit WHERE seq = 4');
        $row = $this->db->selectRow('SELECT seq, mac FROM ?_audit WHERE seq = 3');
        file_put_contents($this->anchor, "3:{$row['mac']}:" . str_repeat('a', 64) . "\n");
        self::assertFalse($this->trail->verify()->intact);
    }

    public function testFreeTextCannotBeInjected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->trail->record(AuditAction::Logout, "admin\n{\"forged\":true}", null, '198.51.100.1');
    }
}
