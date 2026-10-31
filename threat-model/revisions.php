<?php // threat-model/revisions.php — Bounded context: Content revisions & preview (roadmap, release 3)
declare(strict_types=1);

use HybridTM\DSL\{AbuseCase, ThreatModel};

return static function (ThreatModel $model): void {
    $s = new AbuseCase('revision-tamper', 'Rewrite content history in the database');
    $s->asA = 'attacker with database write access (SQL injection elsewhere, stolen DB credentials, shared hosting neighbour)';
    $s->iWant = 'edit, delete or insert revisions';
    $s->soThat = 'hide what was published, or get my text published through a rollback';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['bastion-app', 'db'];
    $s->requiredCwes = ['CWE-354', 'CWE-345'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('revision-snooping', 'Read or roll back other authors\' history');
    $s->asA = 'author';
    $s->iWant = 'open the revision history of an entry I may not edit, or restore an old revision of it';
    $s->soThat = 'read removed text or revert someone else\'s work';
    $s->actorId = 'malicious-author';
    $s->assetIds = ['bastion-app'];
    $s->requiredCwes = ['CWE-285'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('unpublished-change-leak', 'See saved changes before they are published');
    $s->asA = 'anonymous visitor';
    $s->iWant = 'read edits to a published page that the editor saved but did not publish';
    $s->soThat = 'learn unreleased information';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['bastion-app'];
    $s->requiredCwes = ['CWE-200'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('preview-token-abuse', 'Forge, replay or share a preview link');
    $s->asA = 'anonymous attacker or another staff member';
    $s->iWant = 'forge a preview token, reuse an old one, or open a colleague\'s preview link';
    $s->soThat = 'read unpublished revisions';
    $s->actorId = 'malicious-author';
    $s->assetIds = ['bastion-app'];
    $s->requiredCwes = ['CWE-345', 'CWE-613', 'CWE-639'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('preview-exposure', 'Leak preview pages through caches, search engines or Referer');
    $s->asA = 'anonymous attacker';
    $s->iWant = 'find preview URLs in search results, shared caches or Referer headers of outgoing links';
    $s->soThat = 'read unpublished revisions';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['bastion-app'];
    $s->requiredCwes = ['CWE-200'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('diff-dos', 'Exhaust memory with a huge revision comparison');
    $s->asA = 'malicious author';
    $s->iWant = 'save two very long revisions and open their comparison repeatedly';
    $s->soThat = 'the quadratic diff exhausts PHP memory or CPU';
    $s->actorId = 'malicious-author';
    $s->assetIds = ['bastion-app'];
    $s->requiredCwes = ['CWE-400'];
    $model->addAbuseCase($s);
};
