<?php
declare(strict_types=1);

namespace Bastion\Tests\SecurityMonitoring;

use Bastion\Audit\Domain\{AuditAction, AuditEntry};
use Bastion\Media\Infrastructure\LocalMediaStorage;
use Bastion\SecurityMonitoring\Application\SecurityPosture;
use PHPUnit\Framework\TestCase;

final class SecurityPostureTest extends TestCase
{
    private const NOW = 1_800_000_000;

    /** @param list<AuditEntry> $audit */
    private function titles(bool $configured, ?array $last, array $audit = []): string
    {
        $p = new SecurityPosture($configured, $last, new LocalMediaStorage(sys_get_temp_dir()), $audit, self::NOW);
        return implode("\n", array_column($p->notices(), 'title'));
    }

    public function testEachWeaknessIsReported(): void
    {
        self::assertStringContainsString('update channel is not configured', $this->titles(false, null));
        self::assertStringContainsString('media stored on the web server', $this->titles(false, null));
        self::assertStringContainsString('never been synced', $this->titles(true, null));
        self::assertStringContainsString('refused', $this->titles(true, ['at' => self::NOW - 60, 'ok' => false]));
        self::assertStringContainsString('out of date', $this->titles(true, ['at' => self::NOW - SecurityPosture::STALE_AFTER - 1, 'ok' => true]));

        $fresh = $this->titles(true, ['at' => self::NOW - 60, 'ok' => true]);
        self::assertStringNotContainsString('ledger', $fresh);
        self::assertStringNotContainsString('update channel', $fresh);
    }

    public function testRecentRejectionsAreCountedOldOnesAreNot(): void
    {
        $e = static fn (int $ago, AuditAction $a) => new AuditEntry(1, self::NOW - $ago, $a, 'updater', 'acme:hello', 'cli', '');
        $titles = $this->titles(true, ['at' => self::NOW, 'ok' => true], [
            $e(3600, AuditAction::UpdateRejected), $e(86400, AuditAction::UpdateRejected),
            $e(30 * 86400, AuditAction::UpdateRejected), $e(60, AuditAction::ExtensionInstalled),
        ]);
        self::assertStringContainsString('2 extension update(s) rejected', $titles);
    }
}
