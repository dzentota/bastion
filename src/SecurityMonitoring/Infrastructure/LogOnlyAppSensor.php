<?php
declare(strict_types=1);

namespace Bastion\SecurityMonitoring\Infrastructure;

use Bastion\SecurityMonitoring\Domain\{ActorKey, AppSensor, DetectionPoint, ResponseAction};
use Psr\Log\LoggerInterface;

/** До установки БД нет: события только журналируются, автоматических ответов нет. */
final class LogOnlyAppSensor implements AppSensor
{
    public function __construct(private readonly LoggerInterface $log)
    {
    }

    public function event(DetectionPoint $point, ActorKey ...$actors): void
    {
        foreach ($actors as $a) {
            $this->log->warning('appsensor.event', ['dp' => $point->value, 'actor' => $a->value, 'phase' => 'install']);
        }
    }

    public function isActive(ResponseAction $action, ActorKey $actor): bool
    {
        return false;
    }

    public function clear(ActorKey $actor): void
    {
    }
}
