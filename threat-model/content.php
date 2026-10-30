<?php // threat-model/content.php — Bounded context: Content
declare(strict_types=1);

use HybridTM\DSL\{AbuseCase, DataAsset, TechnicalAsset, ThreatModel, TrustBoundary};
use HybridTM\Enums\{AssetType, Confidentiality, Integrity, Technology, TrustBoundaryType};

return static function (ThreatModel $model): void {
    $content = new DataAsset('content', 'Entries, blocks and revisions');
    $content->integrity = Integrity::Important;
    $model->addDataAsset($content);

    $s = new AbuseCase('stored-xss-block', 'Inject script through a content block');
    $s->asA = 'malicious author';
    $s->iWant = 'store markup that executes in a reader or admin browser';
    $s->soThat = 'steal an admin session';
    $s->actorId = 'malicious-author';
    $s->assetIds = ['bastion-app'];
    $s->requiredCwes = ['CWE-79'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('csrf-publish', 'Forge a publish/delete request');
    $s->asA = 'anonymous attacker';
    $s->iWant = 'make a logged-in editor submit a forged request';
    $s->soThat = 'publish or delete content';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['bastion-app'];
    $s->requiredCwes = ['CWE-352'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('sqli-content', 'Inject SQL through content queries');
    $s->asA = 'anonymous attacker';
    $s->iWant = 'manipulate a slug or search parameter';
    $s->soThat = 'read or alter the database';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['db'];
    $s->requiredCwes = ['CWE-89'];
    $model->addAbuseCase($s);
};
