<?php // threat-model/search.php — Bounded context: Full-text search (roadmap, release 7)
declare(strict_types=1);

use HybridTM\DSL\{AbuseCase, ThreatModel};

return static function (ThreatModel $model): void {
    $s = new AbuseCase('search-query-injection', 'Smuggle full-text query syntax through the search box');
    $s->asA = 'anonymous attacker';
    $s->iWant = 'send FTS5 or MySQL boolean operators, column filters or quotes as my query';
    $s->soThat = 'search columns that are not meant to be searched, trigger errors, or make the engine do expensive work';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['bastion-app', 'db'];
    $s->requiredCwes = ['CWE-943'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('search-dos', 'Exhaust the database with search requests');
    $s->asA = 'anonymous attacker';
    $s->iWant = 'send very long queries, many terms or one-letter prefix searches';
    $s->soThat = 'every request scans the whole index';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['bastion-app', 'db'];
    $s->requiredCwes = ['CWE-400'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('search-draft-leak', 'Find drafts or unpublished changes through search');
    $s->asA = 'anonymous visitor';
    $s->iWant = 'search for words that exist only in drafts or in saved but unpublished revisions';
    $s->soThat = 'learn unreleased content';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['bastion-app'];
    $s->requiredCwes = ['CWE-200'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('search-reflected-xss', 'Reflect script through the search page');
    $s->asA = 'anonymous attacker';
    $s->iWant = 'send a victim a search link whose query or snippet carries markup';
    $s->soThat = 'it runs on the site\'s origin';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['bastion-app'];
    $s->requiredCwes = ['CWE-79'];
    $model->addAbuseCase($s);
};
