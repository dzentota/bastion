<?php // threat-model/launch.php — Running the public site behind a CDN (roadmap, release 8)
declare(strict_types=1);

use HybridTM\DSL\{AbuseCase, ThreatModel};

return static function (ThreatModel $model): void {
    $s = new AbuseCase('cdn-session-sharing', 'Get a shared cache to hand one visitor\'s session to everyone');
    $s->asA = 'anonymous attacker';
    $s->iWant = 'make the CDN cache a public page together with its Set-Cookie header, or use a public POST endpoint without CSRF protection';
    $s->soThat = 'visitors share a session I know (fixation), or a forged cross-site request changes state';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['bastion-app'];
    $s->requiredCwes = ['CWE-524', 'CWE-352'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('managed-content-override', 'Rewrite architecture decisions in the CMS');
    $s->asA = 'malicious or compromised editor';
    $s->iWant = 'edit, roll back or re-publish a page synced from docs/adr, or plant a page at its address';
    $s->soThat = 'the published decision record differs from the reviewed one in the repository';
    $s->actorId = 'malicious-author';
    $s->assetIds = ['bastion-app'];
    $s->requiredCwes = ['CWE-284', 'CWE-345'];
    $model->addAbuseCase($s);
};
