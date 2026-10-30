<?php
declare(strict_types=1);

namespace Bastion\IdentityAccess\Domain;

enum Capability: string
{
    case ContentEdit = 'content.edit';
    case ContentEditOthers = 'content.edit_others';
    case ContentPublish = 'content.publish';
    case SettingsManage = 'settings.manage';
    case SecurityView = 'security.view';
}
