<?php // threat-model/media.php — Bounded context: Media
declare(strict_types=1);

use HybridTM\DSL\{AbuseCase, DataAsset, TechnicalAsset, ThreatModel, TrustBoundary};
use HybridTM\Enums\{AssetType, Confidentiality, Integrity, Technology, TrustBoundaryType};

return static function (ThreatModel $model): void {
    $storage = new TechnicalAsset('media-storage', 'S3-compatible media storage (Local = Degraded Mode)');
    $storage->type = AssetType::Datastore;
    $storage->technology = Technology::BlockStorage;
    $model->addTechnicalAsset($storage);

    $s = new AbuseCase('upload-rce', 'Upload an executable file');
    $s->asA = 'malicious author';
    $s->iWant = 'upload a PHP or polyglot file';
    $s->soThat = 'execute code on the server';
    $s->actorId = 'malicious-author';
    $s->assetIds = ['media-storage', 'app-filesystem'];
    $s->requiredCwes = ['CWE-434'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('media-path-traversal', 'Traverse paths through media serving');
    $s->asA = 'anonymous attacker';
    $s->iWant = 'request ../ paths via the media controller';
    $s->soThat = 'read config and secrets';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['app-filesystem'];
    $s->requiredCwes = ['CWE-22'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('exif-leak', 'Leak location data from uploaded photos');
    $s->asA = 'anonymous attacker';
    $s->iWant = 'read EXIF metadata of published images';
    $s->soThat = 'locate the author';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['media-storage'];
    $s->requiredCwes = ['CWE-212'];
    $model->addAbuseCase($s);
};
