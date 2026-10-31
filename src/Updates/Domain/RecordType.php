<?php
declare(strict_types=1);

namespace Bastion\Updates\Domain;

enum RecordType: string
{
    case KeyAppend = 'key-append';
    case KeyRevoke = 'key-revoke';
    case Release = 'release';
}
