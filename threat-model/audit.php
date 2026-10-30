<?php // threat-model/audit.php — Bounded context: Audit
declare(strict_types=1);

use HybridTM\DSL\{AbuseCase, DataAsset, ThreatModel};
use HybridTM\Enums\{Confidentiality, Integrity};

return static function (ThreatModel $model): void {
    $trail = new DataAsset('audit-trail', 'Append-only audit trail (HMAC chain)');
    $trail->confidentiality = Confidentiality::Internal;
    $trail->integrity = Integrity::Critical;
    $model->addDataAsset($trail);

    // Модель нарушителя: доступ к БД (SQLi, утёкший дамп, панель хостинга) без доступа
    // к файлам var/keys. Против полного root на сервере аудит на том же сервере бессилен —
    // это принятый риск; смягчение — экспорт/копия журнала наружу (позже).
    $s = new AbuseCase('audit-tamper', 'Erase or rewrite traces in the audit trail');
    $s->asA = 'attacker with database access';
    $s->iWant = 'delete, edit, reorder or truncate audit entries';
    $s->soThat = 'hide what I did';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['db'];
    $s->dataAssetIds = ['audit-trail'];
    $s->requiredCwes = ['CWE-117', 'CWE-354'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('audit-repudiation', 'Deny a security-relevant action');
    $s->asA = 'malicious or compromised staff account';
    $s->iWant = 'publish, change roles or approve content without a trace';
    $s->soThat = 'deny responsibility later';
    $s->actorId = 'malicious-author';
    $s->assetIds = ['bastion-app'];
    $s->dataAssetIds = ['audit-trail'];
    $s->requiredCwes = ['CWE-778'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('audit-ui-wipe', 'Clear the audit trail from the admin panel');
    $s->asA = 'compromised admin';
    $s->iWant = 'use the admin UI to delete audit records';
    $s->soThat = 'cover my tracks without database access';
    $s->actorId = 'malicious-author';
    $s->assetIds = ['bastion-app'];
    $s->dataAssetIds = ['audit-trail'];
    $s->requiredCwes = ['CWE-284'];
    $model->addAbuseCase($s);
};
