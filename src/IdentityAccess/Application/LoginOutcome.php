<?php
declare(strict_types=1);

namespace Bastion\IdentityAccess\Application;

enum LoginOutcome
{
    /** Неверные данные ИЛИ временная блокировка — наружу неразличимо (без перечисления аккаунтов). */
    case Rejected;
    case Throttled;
    case SecondFactorRequired;
    case SecondFactorEnrollmentRequired;
    case Authenticated;
}
