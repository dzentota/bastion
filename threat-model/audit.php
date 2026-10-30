<?php // threat-model/audit.php — Bounded context: Audit
declare(strict_types=1);

use HybridTM\DSL\{AbuseCase, DataAsset, TechnicalAsset, ThreatModel, TrustBoundary};
use HybridTM\Enums\{AssetType, Confidentiality, Integrity, Technology, TrustBoundaryType};

return static function (ThreatModel $model): void {
    $s = new AbuseCase('audit-tamper', 'Erase traces from the audit log');
    $s->asA = 'compromised admin';
    $s->iWant = 'delete or edit audit entries';
    $s->soThat = 'hide malicious actions';
    $s->actorId = 'malicious-author';
    $s->assetIds = ['db'];
    $s->requiredCwes = ['CWE-117', 'CWE-778'];
    $model->addAbuseCase($s);
};
