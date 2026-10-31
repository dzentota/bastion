<?php
declare(strict_types=1);

namespace Bastion\Audit\Domain;

/** Закрытый перечень действий: свободный текст в журнал не попадает (CWE-117). */
enum AuditAction: string
{
    case Installed = 'installed';
    case LoginSucceeded = 'login_succeeded';
    case Logout = 'logout';
    case PasswordResetRequested = 'password_reset_requested';
    case PasswordChanged = 'password_changed';
    case SecondFactorEnrolled = 'second_factor_enrolled';
    case EntryCreated = 'entry_created';
    case EntryUpdated = 'entry_updated';
    case EntryPublished = 'entry_published';
    case MediaUploaded = 'media_uploaded';
    case CommentApproved = 'comment_approved';
    case CommentRejected = 'comment_rejected';
    case CommentMarkedSpam = 'comment_spam';
    case SecurityResponse = 'security_response';
    case ExtensionInstalled = 'extension_installed';
    case ExtensionEnabled = 'extension_enabled';
    case ExtensionDisabled = 'extension_disabled';
    case UpdateRejected = 'update_rejected';
    case EmergencyUnlock = 'emergency_unlock';
}
