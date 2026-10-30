<?php // threat-model/identity-access.php — Bounded context: Identity & Access
declare(strict_types=1);

use HybridTM\DSL\{AbuseCase, DataAsset, TechnicalAsset, ThreatModel, TrustBoundary};
use HybridTM\Enums\{AssetType, Confidentiality, Integrity, Technology, TrustBoundaryType};

return static function (ThreatModel $model): void {
    $creds = new DataAsset('credentials', 'Password hashes, passkeys, TOTP seeds');
    $creds->confidentiality = Confidentiality::StrictlyConfidential;
    $model->addDataAsset($creds);

    $session = new DataAsset('session-tokens', 'Session and remember-me tokens');
    $session->confidentiality = Confidentiality::StrictlyConfidential;
    $model->addDataAsset($session);

    $s = new AbuseCase('credential-stuffing', 'Credential stuffing against the admin login');
    $s->asA = 'anonymous attacker';
    $s->iWant = 'try leaked passwords against the login form';
    $s->soThat = 'take over a staff account';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['bastion-app'];
    $s->requiredCwes = ['CWE-307', 'CWE-308'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('session-hijack', 'Hijack a staff session');
    $s->asA = 'anonymous attacker';
    $s->iWant = 'steal or fix a staff session token';
    $s->soThat = 'act as an administrator';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['bastion-app'];
    $s->requiredCwes = ['CWE-384', 'CWE-614'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('privilege-escalation', 'Author escalates to admin capabilities');
    $s->asA = 'malicious author';
    $s->iWant = 'call actions outside my capabilities';
    $s->soThat = 'publish or change settings I am not allowed to';
    $s->actorId = 'malicious-author';
    $s->assetIds = ['bastion-app'];
    $s->requiredCwes = ['CWE-285'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('reset-token-theft', 'Abuse the password reset flow');
    $s->asA = 'anonymous attacker';
    $s->iWant = 'guess, replay or leak a reset token';
    $s->soThat = 'set a new password for a victim';
    $s->actorId = 'anonymous-attacker';
    $s->assetIds = ['bastion-app', 'db'];
    $s->requiredCwes = ['CWE-640'];
    $model->addAbuseCase($s);
};
