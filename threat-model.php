<?php // threat-model.php — корневая модель угроз Bastion CMS (Hybridtm DSL)
declare(strict_types=1);
require_once __DIR__ . '/vendor/autoload.php';

use HybridTM\DSL\{DataAsset, TechnicalAsset, ThreatModel, TrustBoundary};
use HybridTM\Enums\{AssetType, BusinessCriticality, Confidentiality, Integrity,
    Machine, Technology, TrustBoundaryType};

$model = new ThreatModel('Bastion CMS');
$model->businessCriticality = BusinessCriticality::Critical;

// ---------------------------------------------------------------------------
// Внешние сущности (акторы)
// ---------------------------------------------------------------------------
$anon = new TechnicalAsset('anonymous-attacker', 'Anonymous Internet Attacker');
$anon->type = AssetType::ExternalEntity;
$anon->technology = Technology::Browser;
$anon->internet = true;
$anon->traits = ['threat_actor'];
$model->addTechnicalAsset($anon);

$visitor = new TechnicalAsset('visitor-browser', 'Visitor / Commenter Browser');
$visitor->type = AssetType::ExternalEntity;
$visitor->technology = Technology::Browser;
$visitor->internet = true;
$visitor->usedAsClientByHuman = true;
$model->addTechnicalAsset($visitor);

$staff = new TechnicalAsset('staff-browser', 'Admin / Editor / Author Browser');
$staff->type = AssetType::ExternalEntity;
$staff->technology = Technology::Browser;
$staff->internet = true;
$staff->usedAsClientByHuman = true;
$model->addTechnicalAsset($staff);

$malAuthor = new TechnicalAsset('malicious-author', 'Malicious or Compromised Staff Account');
$malAuthor->type = AssetType::ExternalEntity;
$malAuthor->technology = Technology::Browser;
$malAuthor->internet = true;
$malAuthor->traits = ['threat_actor'];
$model->addTechnicalAsset($malAuthor);

$malPublisher = new TechnicalAsset('malicious-publisher', 'Malicious Extension Publisher');
$malPublisher->type = AssetType::ExternalEntity;
$malPublisher->technology = Technology::ArtifactRegistry;
$malPublisher->traits = ['threat_actor'];
$model->addTechnicalAsset($malPublisher);

// ---------------------------------------------------------------------------
// Ядро
// ---------------------------------------------------------------------------
$app = new TechnicalAsset('bastion-app', 'Bastion CMS Application');
$app->type = AssetType::Process;
$app->technology = Technology::Cms;
$app->machine = Machine::Virtual; // shared-хостинг
$app->internet = true;
$app->customDevelopedParts = true;
$app->integrity = Integrity::Critical;
$model->addTechnicalAsset($app);

$db = new TechnicalAsset('db', 'Database (MySQL/MariaDB/SQLite)');
$db->type = AssetType::Datastore;
$db->technology = Technology::Database;
$db->confidentiality = Confidentiality::Confidential;
$db->integrity = Integrity::Critical;
$model->addTechnicalAsset($db);

// AppSensor (ADR-0010): встроенный детектор и журнал событий безопасности.
$sensor = new TechnicalAsset('appsensor', 'AppSensor (in-process detection & response)');
$sensor->type = AssetType::Process;
$sensor->technology = Technology::Ids;
$sensor->traits = ['observability_collector'];
$model->addTechnicalAsset($sensor);

$fs = new TechnicalAsset('app-filesystem', 'Hosting Filesystem (code, config, template cache)');
$fs->type = AssetType::Datastore;
$fs->technology = Technology::LocalFileSystem;
$fs->integrity = Integrity::MissionCritical;
$model->addTechnicalAsset($fs);

// ---------------------------------------------------------------------------
// Общие данные
// ---------------------------------------------------------------------------
$secrets = new DataAsset('app-secrets', 'App secrets (DB creds, HMAC/encryption keys)');
$secrets->confidentiality = Confidentiality::StrictlyConfidential;
$model->addDataAsset($secrets);

// ---------------------------------------------------------------------------
// Зоны доверия
// ---------------------------------------------------------------------------
// Внешние акторы находятся вне всех зон доверия (Internet).
$hosting = new TrustBoundary('hosting', 'Shared Hosting Account', TrustBoundaryType::NetworkDedicatedHoster);
$hosting->addAssets('bastion-app', 'appsensor', 'db', 'app-filesystem');
$model->addTrustBoundary($hosting);

// ---------------------------------------------------------------------------
// Фрагменты bounded contexts (ADR-0007, ADR-0008)
// Каждый фрагмент: function (ThreatModel $model): void — добавляет свои
// активы, данные, зоны и Abuser Stories.
// ---------------------------------------------------------------------------
foreach ([
    'installation',
    'identity-access',
    'content',
    'taxonomy',
    'media',
    'comments',
    'theming',
    'extensions',
    'security-monitoring',
    'audit',
    'schema-migrations',
    'i18n',
    'revisions',
] as $context) {
    (require __DIR__ . "/threat-model/{$context}.php")($model);
}

return $model;
