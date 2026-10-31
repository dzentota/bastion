<?php // threat-model.php — корневая модель угроз Bastion CMS (Hybridtm DSL)
declare(strict_types=1);
require_once __DIR__ . '/vendor/autoload.php';

use HybridTM\DSL\{DataAsset, TechnicalAsset, ThreatModel, TrustBoundary};
use HybridTM\DSL\RiskTracking;
use HybridTM\Enums\{Authentication, Authorization, DecisionStatus, Protocol};
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
    'structure',
    'search',
] as $context) {
    (require __DIR__ . "/threat-model/{$context}.php")($model);
}

// ---------------------------------------------------------------------------
// Потоки данных (релиз 6): основа диаграммы DFD на сайте документации.
// ---------------------------------------------------------------------------
$assets = $model->getTechnicalAssets();
$flow = static function (string $from, string $to, Protocol $p, Authentication $authn, Authorization $authz, string $what, array $sent = [], array $received = []) use ($assets): void {
    $link = $assets[$from]->communicatesTo($to, $p, $authn, $authz, $what);
    $link->dataSent = $sent;
    $link->dataReceived = $received;
};
$flow('visitor-browser', 'bastion-app', Protocol::Https, Authentication::None, Authorization::None, 'Read published pages, post comments', ['comments'], ['content', 'media-files']);
$flow('staff-browser', 'bastion-app', Protocol::Https, Authentication::TwoFactor, Authorization::EnduserIdentityPropagation, 'Admin: edit, publish, moderate, configure', ['content', 'media-files', 'credentials'], ['content', 'audit-trail']);
$flow('bastion-app', 'db', Protocol::LocalFileAccess, Authentication::Credentials, Authorization::TechnicalUser, 'SQLite file or MySQL connection', ['content', 'credentials', 'session-tokens', 'comments', 'audit-trail'], ['content', 'credentials', 'session-tokens', 'comments', 'audit-trail']);
$flow('bastion-app', 'app-filesystem', Protocol::LocalFileAccess, Authentication::None, Authorization::TechnicalUser, 'Config, keys, signed template cache', [], ['app-secrets']);
$flow('bastion-app', 'appsensor', Protocol::InProcessLibraryCall, Authentication::None, Authorization::None, 'Detection points and responses');
$flow('bastion-app', 'media-storage', Protocol::Https, Authentication::Credentials, Authorization::TechnicalUser, 'Upload and serve media (S3 API)', ['media-files'], ['media-files']);
$flow('bastion-app', 'media-local', Protocol::LocalFileAccess, Authentication::None, Authorization::TechnicalUser, 'Degraded Mode media outside the webroot', ['media-files'], ['media-files']);
$flow('bastion-app', 'smtp-server', Protocol::SmtpEncrypted, Authentication::Credentials, Authorization::TechnicalUser, 'Password reset mail');
$flow('bastion-app', 'chronicle', Protocol::Https, Authentication::None, Authorization::None, 'Check releases against the update ledger', [], ['extension-registry']);
$flow('bastion-app', 'extension-runtime', Protocol::InProcessLibraryCall, Authentication::None, Authorization::TechnicalUser, 'Capability-checked facades only', ['content']);
$flow('schema-migrator', 'db', Protocol::LocalFileAccess, Authentication::Credentials, Authorization::TechnicalUser, 'Apply schema migrations (after backup)', ['content'], ['content']);

// Решения по находкам анализатора: ложные срабатывания правил о шифровании «в пути» для
// потоков без сетевого транспорта (локальный файл, вызов внутри процесса). Сетевые потоки
// и находки о журналах остаются открытыми и показываются на сайте документации.
foreach ([
    '6247166816fc60c1e2f0f9865c6667a4' => 'bastion-app -> db: SQLite is a local file in the same hosting account; a remote MySQL connection is covered by the operator docs (TLS).',
    '3d4a31484f93d59c61a5483cf4801d7b' => 'bastion-app -> db: local file access, no network transport to encrypt.',
    '152b0b179ec1fae83db869080a751c18' => 'bastion-app -> app-filesystem: local file access inside the hosting account; keys are protected by file permissions (0600), not transport.',
    '7e2ad57e2a3459da59b41563ea66e554' => 'bastion-app -> app-filesystem: local file access, no network transport.',
    'b630ce5d1670b853c4f13bcb2da98e12' => 'bastion-app -> appsensor: in-process library call.',
    'ab08dc160c0242f9460a4fd3204abc13' => 'bastion-app -> media-local: local file access outside the webroot.',
    '5c64e4685d2f54f340455e4cc9b5bcc8' => 'bastion-app -> extension-runtime: in-process call through capability-checked facades.',
    'e1d7cf41b38db9f25dc3aede8fb6f6bb' => 'schema-migrator -> db: same process and local file as the application.',
] as $id => $why) {
    $decision = new RiskTracking($id);
    $decision->status = DecisionStatus::FalsePositive;
    $decision->justification = $why;
    $decision->date = '2026-10-31';
    $model->addRiskTracking($decision);
}

return $model;
