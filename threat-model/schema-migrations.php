<?php // threat-model/schema-migrations.php — Bounded context: Schema Migrations (ADR-0018)
declare(strict_types=1);

use HybridTM\DSL\{AbuseCase, TechnicalAsset, ThreatModel};
use HybridTM\Enums\{AssetType, Integrity, Technology};

return static function (ThreatModel $model): void {
    $migrator = new TechnicalAsset('schema-migrator', 'Schema Migrator (/admin/database, bin/bastion migrate)');
    $migrator->type = AssetType::Process;
    $migrator->technology = Technology::WebApplication;
    $migrator->internet = true;
    $migrator->customDevelopedParts = true;
    $migrator->integrity = Integrity::Critical;
    $model->addTechnicalAsset($migrator);
    $model->getTrustBoundaries()['hosting']->addAssets('schema-migrator');

    $s = new AbuseCase('unauthorized-migration', 'Run schema migrations without being a confirmed administrator');
    $s->asA = 'malicious or compromised staff account, or a cross-site attacker';
    $s->iWant = 'trigger /admin/database (directly or via CSRF from an admin browser)';
    $s->soThat = 'change the schema at a moment of my choosing or destroy data';
    $s->actorId = 'malicious-author';
    $s->assetIds = ['schema-migrator', 'db'];
    $s->requiredCwes = ['CWE-285', 'CWE-352', 'CWE-308'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('tamper-applied-migration', 'Alter an already applied migration');
    $s->asA = 'attacker with write access to the release files or the database';
    $s->iWant = 'change the DDL of an applied migration or forge its record';
    $s->soThat = 'drift the schema silently or hide a destructive change';
    $s->actorId = 'malicious-publisher';
    $s->assetIds = ['schema-migrator', 'db'];
    $s->requiredCwes = ['CWE-354'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('plant-migration', 'Drop a new migration file onto the hosting');
    $s->asA = 'attacker with limited file write (e.g. via another site on shared hosting)';
    $s->iWant = 'place a PHP file next to the migrations';
    $s->soThat = 'have it executed as a migration by the next admin update';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['schema-migrator', 'app-filesystem'];
    $s->requiredCwes = ['CWE-494'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('migration-race', 'Run two migrations concurrently');
    $s->asA = 'anonymous attacker';
    $s->iWant = 'make parallel requests or CLI runs apply the same migration twice';
    $s->soThat = 'corrupt the schema';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['schema-migrator', 'db'];
    $s->requiredCwes = ['CWE-362'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('migration-data-loss', 'Lose data through a failed or wrong migration');
    $s->asA = 'site owner (accidental) or attacker exploiting a broken release';
    $s->iWant = 'have a migration fail half-way or delete data';
    $s->soThat = 'the site cannot be recovered';
    $s->actorId = 'malicious-publisher';
    $s->assetIds = ['schema-migrator', 'db'];
    $s->requiredCwes = ['CWE-1188'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('half-migrated-site', 'Use the site while code and schema disagree');
    $s->asA = 'anonymous attacker';
    $s->iWant = 'hit code paths of the new release before its migrations ran';
    $s->soThat = 'trigger errors that bypass checks or leak details';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['schema-migrator', 'bastion-app'];
    $s->requiredCwes = ['CWE-754'];
    $model->addAbuseCase($s);
};
