<?php
declare(strict_types=1);

namespace Bastion\SecurityMonitoring\Domain;

/** Ответы AppSensor. Автоматически применяются только перечисленные здесь (ADR-0010). */
enum ResponseAction: string
{
    case Log = 'log';
    case Notify = 'notify';
    case Throttle = 'throttle';
    case Logout = 'logout';
    case TemporaryLock = 'temporary_lock';
}
