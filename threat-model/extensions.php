<?php // threat-model/extensions.php — Bounded context: Extensions
declare(strict_types=1);

use HybridTM\DSL\{AbuseCase, DataAsset, TechnicalAsset, ThreatModel, TrustBoundary};
use HybridTM\Enums\{AssetType, Confidentiality, Integrity, Technology, TrustBoundaryType};

return static function (ThreatModel $model): void {
    $ext = new TechnicalAsset('extension-runtime', 'Extension runtime (policy-isolated)');
    $ext->type = AssetType::Process;
    $ext->technology = Technology::Library;
    $model->addTechnicalAsset($ext);

    $chronicle = new TechnicalAsset('chronicle', 'Chronicle / Gossamer ledger');
    $chronicle->type = AssetType::Process;
    $chronicle->technology = Technology::ArtifactRegistry;
    $chronicle->internet = true;
    $model->addTechnicalAsset($chronicle);

    // Каждый вызов Facade расширением журналируется — наблюдаемость внутри зоны расширений.
    $facadeAudit = new TechnicalAsset('extension-facade-audit', 'Extension facade call audit');
    $facadeAudit->type = AssetType::Process;
    $facadeAudit->technology = Technology::Monitoring;
    $facadeAudit->traits = ['observability_collector'];
    $model->addTechnicalAsset($facadeAudit);

    $zone = new TrustBoundary('extension-zone', 'Extension trust zone', TrustBoundaryType::ExecutionEnvironment);
    $zone->addAssets('extension-runtime', 'extension-facade-audit');
    $model->addTrustBoundary($zone);

    $s = new AbuseCase('malicious-extension', 'Ship a backdoored extension');
    $s->asA = 'malicious publisher';
    $s->iWant = 'publish an extension that calls forbidden functions';
    $s->soThat = 'gain code execution on many sites';
    $s->actorId = 'malicious-publisher';
    $s->assetIds = ['extension-runtime'];
    $s->requiredCwes = ['CWE-506'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('capability-overreach', 'Use capabilities beyond the manifest');
    $s->asA = 'malicious publisher';
    $s->iWant = 'reach DB/FS/HTTP without a granted facade';
    $s->soThat = 'exfiltrate data';
    $s->actorId = 'malicious-publisher';
    $s->assetIds = ['extension-runtime', 'db'];
    $s->requiredCwes = ['CWE-269'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('update-hijack', 'Hijack the update channel');
    $s->asA = 'supply-chain attacker';
    $s->iWant = 'serve a tampered release or a stolen publisher key';
    $s->soThat = 'push malware as an update';
    $s->actorId = 'malicious-publisher';
    $s->assetIds = ['chronicle', 'app-filesystem'];
    $s->requiredCwes = ['CWE-494', 'CWE-345'];
    $model->addAbuseCase($s);
};
