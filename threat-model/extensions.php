<?php // threat-model/extensions.php — Bounded context: Extensions (ADR-0012)
declare(strict_types=1);

use HybridTM\DSL\{AbuseCase, DataAsset, TechnicalAsset, ThreatModel, TrustBoundary};
use HybridTM\Enums\{AssetType, Confidentiality, Integrity, Technology, TrustBoundaryType};

return static function (ThreatModel $model): void {
    $ext = new TechnicalAsset('extension-runtime', 'Extension runtime (policy-isolated, facades only)');
    $ext->type = AssetType::Process;
    $ext->technology = Technology::Library;
    $model->addTechnicalAsset($ext);

    $chronicle = new TechnicalAsset('chronicle', 'Chronicle / Gossamer ledger');
    $chronicle->type = AssetType::Process;
    $chronicle->technology = Technology::ArtifactRegistry;
    $chronicle->internet = true;
    $model->addTechnicalAsset($chronicle);

    $registry = new DataAsset('extension-registry', 'Installed extensions: pinned keys, file hashes, granted capabilities');
    $registry->integrity = Integrity::MissionCritical;
    $model->addDataAsset($registry);

    // Каждый вызов Facade расширением журналируется — наблюдаемость внутри зоны расширений.
    $facadeAudit = new TechnicalAsset('extension-facade-audit', 'Extension facade call audit');
    $facadeAudit->type = AssetType::Process;
    $facadeAudit->technology = Technology::Monitoring;
    $facadeAudit->traits = ['observability_collector'];
    $model->addTechnicalAsset($facadeAudit);

    $zone = new TrustBoundary('extension-zone', 'Extension trust zone', TrustBoundaryType::ExecutionEnvironment);
    $zone->addAssets('extension-runtime', 'extension-facade-audit');
    $model->addTrustBoundary($zone);

    $story = static function (string $id, string $title, string $asA, string $iWant, string $soThat, string $actor, array $assets, array $cwes) use ($model): void {
        $s = new AbuseCase($id, $title);
        $s->asA = $asA;
        $s->iWant = $iWant;
        $s->soThat = $soThat;
        $s->actorId = $actor;
        $s->assetIds = $assets;
        $s->requiredCwes = $cwes;
        $model->addAbuseCase($s);
    };

    $story('malicious-extension', 'Ship a backdoored extension', 'malicious publisher',
        'publish an extension that runs shell commands, reads files or calls the network', 'gain code execution on many sites',
        'malicious-publisher', ['extension-runtime'], ['CWE-506']);
    $story('capability-overreach', 'Use capabilities beyond the manifest', 'malicious publisher',
        'reach the database, sessions or settings without a granted facade', 'exfiltrate data or take over the site',
        'malicious-publisher', ['extension-runtime', 'db'], ['CWE-269']);
    $story('extension-static-gate-bypass', 'Smuggle forbidden code past the Static Gate', 'malicious publisher',
        'use dynamic calls, string callables, variable variables or encoding tricks', 'execute a forbidden function after review',
        'malicious-publisher', ['extension-runtime'], ['CWE-184']);
    $story('extension-zip-slip', 'Write outside the extension directory', 'malicious publisher',
        'put ../ paths, absolute paths or symlinks into the package', 'overwrite core files or config',
        'malicious-publisher', ['app-filesystem'], ['CWE-22']);
    $story('extension-archive-bomb', 'Exhaust the server with the package itself', 'malicious publisher',
        'upload a zip bomb or an archive with thousands of entries', 'take the site down during installation',
        'malicious-publisher', ['bastion-app'], ['CWE-409']);
    $story('extension-disk-tamper', 'Modify an installed extension on disk', 'attacker with file write (FTP leak, other site on the host)',
        'edit the PHP files of an approved extension after installation', 'run code that was never reviewed or signed',
        'anonymous-attacker', ['app-filesystem', 'extension-runtime'], ['CWE-345']);
    $story('extension-key-substitution', 'Replace an extension with one signed by another key', 'impersonating publisher',
        'upload a new version of a known extension signed with my own key', 'hijack an extension the admin already trusts',
        'malicious-publisher', ['extension-runtime'], ['CWE-347']);
    $story('update-hijack', 'Hijack the update channel', 'supply-chain attacker',
        'serve a tampered release or a stolen publisher key', 'push malware as an update',
        'malicious-publisher', ['chronicle', 'app-filesystem'], ['CWE-494', 'CWE-345']);
};
