<?php // threat-model/media.php — Bounded context: Media (ADR-0011)
declare(strict_types=1);

use HybridTM\DSL\{AbuseCase, DataAsset, TechnicalAsset, ThreatModel, TrustBoundary};
use HybridTM\Enums\{AssetType, Confidentiality, Integrity, Technology, TrustBoundaryType};

return static function (ThreatModel $model): void {
    $files = new DataAsset('media-files', 'Uploaded media files');
    $files->confidentiality = Confidentiality::Public;
    $files->integrity = Integrity::Important;
    $model->addDataAsset($files);

    $creds = new DataAsset('storage-credentials', 'S3 access key / secret');
    $creds->confidentiality = Confidentiality::StrictlyConfidential;
    $model->addDataAsset($creds);

    // По умолчанию — внешнее S3-совместимое хранилище: загруженный файл физически
    // не лежит рядом с PHP-кодом, RCE через загрузку исключается как класс.
    $storage = new TechnicalAsset('media-storage', 'S3-compatible object storage');
    $storage->type = AssetType::Datastore;
    $storage->technology = Technology::BlockStorage;
    $storage->internet = true;
    $storage->dataAssetsStored = ['media-files'];
    $model->addTechnicalAsset($storage);

    // Degraded Mode: локальное хранилище вне webroot (var/media).
    $local = new TechnicalAsset('media-local', 'Local media storage (Degraded Mode, outside webroot)');
    $local->type = AssetType::Datastore;
    $local->technology = Technology::LocalFileSystem;
    $local->dataAssetsStored = ['media-files'];
    $model->addTechnicalAsset($local);
    $model->getTrustBoundaries()['hosting']->addAssets('media-local');

    $s = new AbuseCase('upload-rce', 'Upload an executable file');
    $s->asA = 'malicious author';
    $s->iWant = 'upload a PHP script or a polyglot image';
    $s->soThat = 'execute code on the server';
    $s->actorId = 'malicious-author';
    $s->assetIds = ['media-local', 'app-filesystem'];
    $s->requiredCwes = ['CWE-434'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('media-path-traversal', 'Traverse paths through media upload or serving');
    $s->asA = 'anonymous attacker';
    $s->iWant = 'use ../ in a file name or media URL';
    $s->soThat = 'read or overwrite config and secrets';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['media-local', 'app-filesystem'];
    $s->requiredCwes = ['CWE-22'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('exif-leak', 'Leak location data from uploaded photos');
    $s->asA = 'anonymous attacker';
    $s->iWant = 'read EXIF GPS metadata of published images';
    $s->soThat = 'locate the author';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['media-storage', 'media-local'];
    $s->requiredCwes = ['CWE-212'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('media-decompression-bomb', 'Exhaust memory with a decompression bomb');
    $s->asA = 'malicious author';
    $s->iWant = 'upload a tiny image that decodes to gigapixels';
    $s->soThat = 'crash PHP workers and take the site down';
    $s->actorId = 'malicious-author';
    $s->assetIds = ['bastion-app'];
    $s->requiredCwes = ['CWE-409'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('media-content-sniffing', 'Make the browser execute an uploaded file');
    $s->asA = 'malicious author';
    $s->iWant = 'upload HTML/SVG/scriptable PDF disguised as media';
    $s->soThat = 'run script in the site origin when a visitor or admin opens it';
    $s->actorId = 'malicious-author';
    $s->assetIds = ['bastion-app'];
    $s->requiredCwes = ['CWE-79', 'CWE-430'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('storage-endpoint-ssrf', 'Point the storage endpoint at an internal service');
    $s->asA = 'compromised admin';
    $s->iWant = 'set the S3 endpoint to 169.254.169.254 or an intranet host';
    $s->soThat = 'read cloud metadata or attack internal services from the server';
    $s->actorId = 'malicious-author';
    $s->assetIds = ['bastion-app'];
    $s->requiredCwes = ['CWE-918'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('storage-credential-leak', 'Steal object storage credentials');
    $s->asA = 'anonymous attacker';
    $s->iWant = 'read S3 keys from config, logs or responses';
    $s->soThat = 'delete or replace every media file';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['app-filesystem'];
    $s->dataAssetIds = ['storage-credentials'];
    $s->requiredCwes = ['CWE-522'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('upload-flood', 'Exhaust storage with uploads');
    $s->asA = 'malicious author';
    $s->iWant = 'upload thousands of large files';
    $s->soThat = 'fill the hosting quota and break the site';
    $s->actorId = 'malicious-author';
    $s->assetIds = ['media-storage', 'media-local'];
    $s->requiredCwes = ['CWE-770'];
    $model->addAbuseCase($s);
};
