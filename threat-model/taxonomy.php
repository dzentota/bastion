<?php // threat-model/taxonomy.php — Bounded context: Taxonomy
declare(strict_types=1);

use HybridTM\DSL\{AbuseCase, DataAsset, TechnicalAsset, ThreatModel, TrustBoundary};
use HybridTM\Enums\{AssetType, Confidentiality, Integrity, Technology, TrustBoundaryType};

return static function (ThreatModel $model): void {
    $s = new AbuseCase('term-enumeration-dos', 'Exhaust resources via taxonomy listing');
    $s->asA = 'anonymous attacker';
    $s->iWant = 'request huge or crafted term listings';
    $s->soThat = 'slow the site down';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['bastion-app', 'db'];
    $s->requiredCwes = ['CWE-400'];
    $model->addAbuseCase($s);
};
