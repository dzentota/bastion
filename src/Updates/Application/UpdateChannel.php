<?php
declare(strict_types=1);

namespace Bastion\Updates\Application;

use Bastion\Audit\Domain\{AuditAction, AuditTrail};
use Bastion\Extensions\Application\{ExtensionInstaller, PackageReader, PackageSignature, ReleaseAttestor};
use Bastion\Extensions\Domain\{ExtensionVersion, InvalidPackage, Manifest};
use Bastion\Extensions\Infrastructure\ExtensionRegistry;
use Bastion\Updates\Domain\{InvalidRecord, LedgerRecord};
use Bastion\Updates\Infrastructure\LedgerStore;
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};
use Psr\Log\LoggerInterface;

/**
 * Обновления расширений по модели Gossamer/Airship (ADR-0014):
 * журнал Chronicle (подпись сервера + хэш-цепочка) → состояние ключей издателей → релиз ставится,
 * только если его BLAKE2b-512 записан в журнале активным ключом. Отзыв ключа выключает
 * уже установленные расширения этого ключа.
 */
#[AbuserStory('update-hijack')]
#[Mitigation(cwe: 'CWE-494', description: 'Updates install only if the package BLAKE2b-512 digest is recorded in the append-only Chronicle ledger by an active publisher key, in addition to the package signature; registry server is untrusted')]
#[Mitigation(cwe: 'CWE-345', description: 'Chronicle responses verified with a pinned server key and a hash chain continuing the local head (no rewrite, fork or rollback); local replica HMAC-protected; revoked (stolen) keys disable their extensions and cannot sign releases')]
#[AssetId('app-filesystem')]
final class UpdateChannel implements ReleaseAttestor
{
    private ?TrustState $state = null;

    public function __construct(
        private readonly UpdateConfig $config,
        private readonly UpdateTransport $transport,
        private readonly LedgerStore $ledger,
        private readonly ExtensionRegistry $registry,
        private readonly AuditTrail $audit,
        private readonly LoggerInterface $log,
    ) {
    }

    /**
     * Догоняет журнал. Возвращает число новых записей.
     * @throws InvalidRecord
     */
    public function sync(): int
    {
        $head = $this->ledger->head();
        $url = rtrim($this->config->chronicleUrl, '/') . ($head === '' ? '/chronicle/export' : '/chronicle/since/' . rawurlencode($head));
        $res = $this->transport->get($url, ChronicleFeed::MAX_BODY);
        if ($res['status'] !== 200) {
            throw new InvalidRecord("Chronicle answered HTTP {$res['status']}");
        }
        $entries = ChronicleFeed::verify($res['body'], $res['signature'], $this->config->chronicleKey, $head);
        $this->ledger->append($entries);
        $this->state = null;
        $this->disableRevoked();
        return count($entries);
    }

    /**
     * Проверяет и ставит новые версии установленных расширений.
     * @return list<string> строки отчёта
     */
    public function run(ExtensionInstaller $installer): array
    {
        $report = [];
        foreach ($this->registry->all() as $ext) {
            $name = $ext->manifest->name;
            $base = rtrim($this->config->registryUrl, '/') . '/' . $name->vendor() . '/' . $name->package();
            try {
                $latest = $this->transport->get($base . '/latest.json', 4096);
                $d = $latest['status'] === 200 ? json_decode($latest['body'], true, 2) : null;
                if (!is_array($d) || !ExtensionVersion::tryParse($d['version'] ?? null, $version)) {
                    throw new InvalidPackage('Registry gave no valid latest version');
                }
                if (!$version->isNewerThan($ext->manifest->version)) {
                    continue;
                }
                $zip = $this->transport->get($base . '/' . $version->toNative() . '.zip', PackageReader::MAX_ARCHIVE);
                $sig = $this->transport->get($base . '/' . $version->toNative() . '.zip.sig', 1024);
                if ($zip['status'] !== 200 || $sig['status'] !== 200) {
                    throw new InvalidPackage('Release files are not available');
                }
                $installed = $installer->install($zip['body'], $sig['body'], 'updater', 'cli');
                $report[] = "Updated {$name->toNative()} to {$installed->manifest->version->toNative()}" . ($installed->enabled ? '' : ' (disabled: review new permissions)');
            } catch (InvalidPackage | InvalidRecord $e) {
                $this->audit->record(AuditAction::UpdateRejected, 'updater', str_replace('/', ':', $name->toNative()), 'cli');
                $this->log->warning('update.rejected', ['extension' => $name->toNative(), 'reason' => $e->getMessage()]);
                $report[] = "Rejected update of {$name->toNative()}: {$e->getMessage()}";
            }
        }
        return $report;
    }

    public function attest(Manifest $manifest, string $zipBytes): void
    {
        $why = $this->state()->attest($manifest->name, $manifest->version, bin2hex(PackageSignature::digest($zipBytes)), $manifest->publisher);
        if ($why !== null) {
            throw new InvalidPackage($why);
        }
    }

    public function allowsRotation(Manifest $previous, Manifest $next): bool
    {
        $vendor = $next->name->vendor();
        $s = $this->state();
        // закреплённый ключ обязан быть в истории издателя в журнале: иначе самоподписанный
        // bootstrap чужого ключа для «нового» издателя выдавался бы за ротацию
        $pinnedKnown = $s->isActive($vendor, $previous->publisher) || $s->isRevoked($vendor, $previous->publisher);
        return $pinnedKnown && $s->isActive($vendor, $next->publisher);
    }

    private function disableRevoked(): void
    {
        foreach ($this->registry->all() as $ext) {
            if ($ext->enabled && $this->state()->isRevoked($ext->manifest->name->vendor(), $ext->manifest->publisher)) {
                $json = $this->registry->manifestJson($ext->manifest->name);
                if ($json !== null) {
                    $this->registry->save(new \Bastion\Extensions\Domain\InstalledExtension($ext->manifest, $ext->fileHashes, [], false), $json);
                    $this->audit->record(AuditAction::ExtensionDisabled, 'updater', str_replace('/', ':', $ext->manifest->name->toNative()), 'cli');
                    $this->log->warning('update.key_revoked', ['extension' => $ext->manifest->name->toNative()]);
                }
            }
        }
    }

    private function state(): TrustState
    {
        if ($this->state === null) {
            $this->state = new TrustState($this->config->superProvider);
            foreach ($this->ledger->contents() as $contents) {
                try {
                    $this->state->apply(LedgerRecord::parse($contents));
                } catch (InvalidRecord) {
                    // мусор в публичном журнале игнорируется
                }
            }
        }
        return $this->state;
    }
}
