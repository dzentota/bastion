<?php // threat-model/comments.php — Bounded context: Comments
declare(strict_types=1);

use HybridTM\DSL\{AbuseCase, DataAsset, ThreatModel};
use HybridTM\Enums\{Confidentiality, Integrity};

return static function (ThreatModel $model): void {
    $comments = new DataAsset('comments', 'Visitor comments and moderation state');
    $comments->integrity = Integrity::Important;
    $model->addDataAsset($comments);

    // Правило 0: email не собираем, IP храним только как HMAC (для лимитов и модерации).
    $pii = new DataAsset('commenter-fingerprint', 'Keyed hash of commenter IP');
    $pii->confidentiality = Confidentiality::Confidential;
    $model->addDataAsset($pii);

    $s = new AbuseCase('comment-xss', 'Inject script through a comment');
    $s->asA = 'anonymous attacker';
    $s->iWant = 'submit a comment that executes in a visitor or moderator browser';
    $s->soThat = 'take over the moderator session';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['bastion-app'];
    $s->dataAssetIds = ['comments'];
    $s->requiredCwes = ['CWE-79'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('comment-spam-flood', 'Flood the moderation queue');
    $s->asA = 'anonymous attacker';
    $s->iWant = 'submit thousands of comments with a bot';
    $s->soThat = 'drown legitimate comments and exhaust storage';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['bastion-app', 'db'];
    $s->requiredCwes = ['CWE-770', 'CWE-799'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('comment-moderation-bypass', 'Publish a comment without moderation');
    $s->asA = 'anonymous attacker or author without the capability';
    $s->iWant = 'approve my own comment or forge a moderation request';
    $s->soThat = 'publish spam or abuse on the site';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['bastion-app'];
    $s->dataAssetIds = ['comments'];
    $s->requiredCwes = ['CWE-285'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('commenter-deanonymisation', 'Learn who wrote a comment');
    $s->asA = 'attacker who obtained a database dump';
    $s->iWant = 'read commenter IP addresses or emails';
    $s->soThat = 'identify and target commenters';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['db'];
    $s->dataAssetIds = ['commenter-fingerprint'];
    $s->requiredCwes = ['CWE-359'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('comment-impersonation', 'Impersonate the site owner in comments');
    $s->asA = 'anonymous attacker';
    $s->iWant = 'use bidi overrides or the owner name as my display name';
    $s->soThat = 'make readers trust a malicious comment';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['bastion-app'];
    $s->requiredCwes = ['CWE-451'];
    $model->addAbuseCase($s);
};
