<?php // threat-model/security-monitoring.php — Bounded context: Security Monitoring (AppSensor)
declare(strict_types=1);

use HybridTM\DSL\{AbuseCase, DataAsset, TechnicalAsset, ThreatModel, TrustBoundary};
use HybridTM\Enums\{AssetType, Confidentiality, Integrity, Technology, TrustBoundaryType};

return static function (ThreatModel $model): void {
    $s = new AbuseCase('appsensor-lockout-abuse', 'Abuse automated responses to lock out the admin');
    $s->asA = 'anonymous attacker';
    $s->iWant = 'trigger detection points on behalf of the admin';
    $s->soThat = 'lock the owner out of their site';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['bastion-app'];
    $s->requiredCwes = ['CWE-645'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('appsensor-evasion', 'Stay below detection thresholds');
    $s->asA = 'anonymous attacker';
    $s->iWant = 'spread probes across IPs and time';
    $s->soThat = 'attack without triggering responses';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['bastion-app'];
    $s->requiredCwes = ['CWE-778'];
    $model->addAbuseCase($s);
};
