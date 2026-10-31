<?php // threat-model/i18n.php — Bounded context: Content translations (roadmap, release 2)
declare(strict_types=1);

use HybridTM\DSL\{AbuseCase, ThreatModel};

return static function (ThreatModel $model): void {
    $s = new AbuseCase('translation-hijack', 'Attach a translation to someone else\'s entry');
    $s->asA = 'author';
    $s->iWant = 'add a language variant to an entry I may not edit, or a second variant in the same language';
    $s->soThat = 'my text appears as the official translation of another author\'s page';
    $s->actorId = 'malicious-author';
    $s->assetIds = ['bastion-app', 'db'];
    $s->requiredCwes = ['CWE-285'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('language-parameter-abuse', 'Smuggle values through the language parameter');
    $s->asA = 'anonymous attacker';
    $s->iWant = 'put arbitrary codes into /{lang}/… or the editor\'s language field';
    $s->soThat = 'inject markup into lang/hreflang attributes, create unreachable entries or enumerate content';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['bastion-app'];
    $s->requiredCwes = ['CWE-20'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('draft-translation-leak', 'Read an unpublished translation');
    $s->asA = 'anonymous visitor';
    $s->iWant = 'follow the language switcher or hreflang links of a published page';
    $s->soThat = 'reach a translation that is still a draft';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['bastion-app'];
    $s->requiredCwes = ['CWE-200'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('catalog-injection', 'Execute code or inject markup through string catalogs');
    $s->asA = 'attacker with limited file write on the hosting';
    $s->iWant = 'drop a catalog file with code or HTML into translations/';
    $s->soThat = 'run code or show script to administrators';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['bastion-app', 'app-filesystem'];
    $s->requiredCwes = ['CWE-94'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('ui-locale-tampering', 'Abuse the admin language switch');
    $s->asA = 'cross-site attacker or another staff member';
    $s->iWant = 'set an arbitrary or someone else\'s interface language, or bounce through the switch to another site';
    $s->soThat = 'break the admin for a victim or use the redirect for phishing';
    $s->actorId = 'malicious-author';
    $s->assetIds = ['bastion-app'];
    $s->requiredCwes = ['CWE-20', 'CWE-601'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('legacy-redirect-abuse', 'Turn pre-i18n URL redirects into an open redirect');
    $s->asA = 'anonymous attacker';
    $s->iWant = 'craft an old-style /{slug} URL that redirects off-site';
    $s->soThat = 'phish visitors through the site\'s domain';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['bastion-app'];
    $s->requiredCwes = ['CWE-601'];
    $model->addAbuseCase($s);
};
