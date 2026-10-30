<?php
declare(strict_types=1);

namespace Bastion\IdentityAccess\Domain;

enum Capability: string
{
    case ContentEdit = 'content.edit';
    case ContentEditOthers = 'content.edit_others';
    case ContentPublish = 'content.publish';
    case MediaUpload = 'media.upload';
    case CommentsModerate = 'comments.moderate';
    case SettingsManage = 'settings.manage';
    case SecurityView = 'security.view';
}
