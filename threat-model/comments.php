<?php // threat-model/comments.php — Bounded context: Comments
declare(strict_types=1);

use HybridTM\DSL\{AbuseCase, DataAsset, TechnicalAsset, ThreatModel, TrustBoundary};
use HybridTM\Enums\{AssetType, Confidentiality, Integrity, Technology, TrustBoundaryType};

return static function (ThreatModel $model): void {
    $s = new AbuseCase('comment-xss', 'Inject script through a comment');
    $s->asA = 'anonymous attacker';
    $s->iWant = 'submit a comment that executes in the moderator browser';
    $s->soThat = 'take over the moderator session';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['bastion-app'];
    $s->requiredCwes = ['CWE-79'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('comment-spam-flood', 'Flood the moderation queue');
    $s->asA = 'anonymous attacker';
    $s->iWant = 'submit thousands of comments';
    $s->soThat = 'drown legitimate comments and exhaust storage';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['bastion-app', 'db'];
    $s->requiredCwes = ['CWE-770'];
    $model->addAbuseCase($s);
};
