<?php // threat-model/theming.php — Bounded context: Theming
declare(strict_types=1);

use HybridTM\DSL\{AbuseCase, DataAsset, TechnicalAsset, ThreatModel, TrustBoundary};
use HybridTM\Enums\{AssetType, Confidentiality, Integrity, Technology, TrustBoundaryType};

return static function (ThreatModel $model): void {
    $s = new AbuseCase('template-code-exec', 'Execute code through a theme template');
    $s->asA = 'malicious theme publisher';
    $s->iWant = 'ship a template that escapes the DSL';
    $s->soThat = 'run arbitrary PHP';
    $s->actorId = 'malicious-publisher';
    $s->assetIds = ['bastion-app'];
    $s->requiredCwes = ['CWE-94', 'CWE-1336'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('template-cache-tamper', 'Tamper with the compiled template cache');
    $s->asA = 'attacker with file write';
    $s->iWant = 'modify a compiled template on disk';
    $s->soThat = 'get it executed on next render';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['app-filesystem'];
    $s->requiredCwes = ['CWE-494'];
    $model->addAbuseCase($s);
};
