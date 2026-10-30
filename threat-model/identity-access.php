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

    $mail = new TechnicalAsset('smtp-server', 'SMTP relay (outgoing mail)');
    $mail->type = AssetType::ExternalEntity;
    $mail->technology = Technology::MailServer;
    $mail->internet = true;
    $model->addTechnicalAsset($mail);

    $story = static function (string $id, string $title, string $asA, string $iWant, string $soThat, string $actor, array $assets, array $cwes) use ($model): void {
        $s = new AbuseCase($id, $title);
        $s->asA = $asA;
        $s->iWant = $iWant;
        $s->soThat = $soThat;
        $s->actorId = $actor;
        $s->assetIds = $assets;
        $s->requiredCwes = $cwes;
        $model->addAbuseCase($s);
    };

    $story('reset-token-theft', 'Abuse the password reset token', 'anonymous attacker',
        'guess, replay, reuse or leak a reset token (logs, history, Referer, DB dump)', 'set a new password for a victim',
        'anonymous-attacker', ['bastion-app', 'db'], ['CWE-640']);
    $story('reset-account-enumeration', 'Learn which emails have accounts', 'anonymous attacker',
        'compare reset responses for different emails', 'target real staff accounts',
        'anonymous-attacker', ['bastion-app'], ['CWE-204']);
    $story('reset-host-poisoning', 'Poison the reset link host', 'anonymous attacker',
        'send a reset request with a forged Host header', 'receive the victim\'s token on my server when they click',
        'anonymous-attacker', ['bastion-app'], ['CWE-644']);
    $story('mail-header-injection', 'Inject headers into outgoing mail', 'anonymous attacker',
        'put CRLF sequences into an email address or name', 'add recipients or rewrite the message',
        'anonymous-attacker', ['bastion-app', 'smtp-server'], ['CWE-93']);
    $story('reset-mail-flood', 'Flood a victim with reset emails', 'anonymous attacker',
        'trigger thousands of reset emails', 'harass staff and get the site blacklisted as spam',
        'anonymous-attacker', ['bastion-app', 'smtp-server'], ['CWE-799']);
    $story('reset-session-persistence', 'Keep access after the victim resets the password', 'attacker with a stolen session',
        'keep using my session after the owner changes the password', 'retain control of the account',
        'anonymous-attacker', ['bastion-app'], ['CWE-613']);
    $story('smtp-cleartext', 'Read reset links or SMTP credentials on the wire', 'network attacker',
        'downgrade or intercept the SMTP connection', 'steal reset tokens and the mail password',
        'anonymous-attacker', ['smtp-server'], ['CWE-319']);
};
