<?php
declare(strict_types=1);

namespace Bastion\SecurityMonitoring\Domain;

/** Порт: регистрирует события и отвечает, активен ли ответ для актора. */
interface AppSensor
{
    public function event(DetectionPoint $point, ActorKey ...$actors): void;

    public function isActive(ResponseAction $action, ActorKey $actor): bool;

    /** Аварийный сброс блокировок (Emergency Access, CLI). */
    public function clear(ActorKey $actor): void;
}
