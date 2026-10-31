<?php
declare(strict_types=1);

namespace Bastion\SecurityMonitoring\Application;

use Bastion\Audit\Domain\{AuditAction, AuditEntry};
use Bastion\Media\Domain\MediaStorage;

/**
 * Что сейчас ослабляет защиту сайта — для постоянного показа в админке (Degraded Mode, ADR-0011/0014).
 * Тексты фиксированы кодом; из внешних данных в них попадают только числа и даты.
 */
final class SecurityPosture
{
    public const STALE_AFTER = 48 * 3600;
    private const REJECTIONS_WINDOW = 7 * 86400;

    /**
     * @param array{at: int, ok: bool}|null $lastUpdateRun
     * @param list<AuditEntry> $recentAudit
     */
    public function __construct(
        private readonly bool $updatesConfigured,
        private readonly ?array $lastUpdateRun,
        private readonly MediaStorage $media,
        private readonly array $recentAudit,
        private readonly int $now,
    ) {
    }

    /** @return list<array{level: string, title: string, detail: string}> */
    public function notices(): array
    {
        $out = [];
        if (!$this->updatesConfigured) {
            $out[] = ['level' => 'warning', 'title' => 'Degraded Mode: update channel is not configured',
                'detail' => 'Extensions are installed only by manual upload with a pinned publisher key; releases are not checked against the update ledger and revoked keys are not detected. Configure updates.* in config.json and run bin/bastion updates:run from cron.'];
        } elseif ($this->lastUpdateRun === null) {
            $out[] = ['level' => 'warning', 'title' => 'Update ledger has never been synced',
                'detail' => 'Run bin/bastion updates:run and schedule it in cron.'];
        } elseif (!$this->lastUpdateRun['ok']) {
            $out[] = ['level' => 'danger', 'title' => 'Last update run was refused',
                'detail' => 'The update ledger could not be verified on ' . gmdate('Y-m-d H:i', $this->lastUpdateRun['at']) . ' UTC. See var/log/security.log; the ledger may be forged or forked.'];
        } elseif ($this->now - $this->lastUpdateRun['at'] > self::STALE_AFTER) {
            $out[] = ['level' => 'warning', 'title' => 'Update ledger is out of date',
                'detail' => 'Last successful sync: ' . gmdate('Y-m-d H:i', $this->lastUpdateRun['at']) . ' UTC. Key revocations are applied only on sync — check the cron job.'];
        }
        $rejected = count(array_filter($this->recentAudit, fn (AuditEntry $e) => $e->action === AuditAction::UpdateRejected && $this->now - $e->at <= self::REJECTIONS_WINDOW));
        if ($rejected > 0) {
            $out[] = ['level' => 'danger', 'title' => "{$rejected} extension update(s) rejected in the last 7 days",
                'detail' => 'A release did not match the update ledger. This can mean a compromised registry. Details are in the audit log and var/log/security.log.'];
        }
        if ($this->media->isDegraded()) {
            $out[] = ['level' => 'warning', 'title' => 'Degraded Mode: media stored on the web server',
                'detail' => 'Uploads are kept in var/media outside the webroot. An isolated object storage (media.driver = s3) is recommended.'];
        }
        return $out;
    }
}
