<?php // threat-model/installation.php — Bounded context: Installation & Configuration
declare(strict_types=1);

use HybridTM\DSL\{AbuseCase, DataAsset, TechnicalAsset, ThreatModel, TrustBoundary};
use HybridTM\Enums\{AssetType, Confidentiality, Integrity, Technology, TrustBoundaryType};

return static function (ThreatModel $model): void {
    $installer = new TechnicalAsset('installer', 'Web Installer');
    $installer->type = AssetType::Process;
    $installer->technology = Technology::WebApplication;
    $installer->internet = true;
    $model->addTechnicalAsset($installer);
    $model->getTrustBoundaries()['hosting']->addAssets('installer');

    $s = new AbuseCase('hijack-installer', 'Take over a fresh installation via the web installer');
    $s->asA = 'anonymous attacker';
    $s->iWant = 'run the installer on a freshly uploaded site before the owner';
    $s->soThat = 'become its administrator';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['installer'];
    $s->requiredCwes = ['CWE-306'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('reinstall-over-live', 'Re-run the installer on a live site');
    $s->asA = 'anonymous attacker';
    $s->iWant = 'reach the installer after installation finished';
    $s->soThat = 'reset the admin account or DB settings';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['installer', 'app-filesystem'];
    $s->requiredCwes = ['CWE-284'];
    $model->addAbuseCase($s);
};
