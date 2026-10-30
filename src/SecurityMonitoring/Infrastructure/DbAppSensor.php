<?php
declare(strict_types=1);

namespace Bastion\SecurityMonitoring\Infrastructure;

use Bastion\SecurityMonitoring\Domain\{ActorKey, AppSensor, DetectionPoint, ResponseAction};
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use SecureDb\Db;
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};

#[AbuserStory('appsensor-lockout-abuse')]
#[Mitigation(cwe: 'CWE-645', description: 'Account locks are temporary; IP and account counters are separate; emergency clear via bin/bastion')]
#[AbuserStory('appsensor-evasion')]
#[Mitigation(cwe: 'CWE-778', description: 'AE2 counts failures per account regardless of source IP, so distributed guessing is still detected')]
#[AssetId('appsensor')]
final class DbAppSensor implements AppSensor
{
    public function __construct(
        private readonly Db $db,
        private readonly ClockInterface $clock,
        private readonly LoggerInterface $log,
    ) {
    }

    public function event(DetectionPoint $point, ActorKey ...$actors): void
    {
        $now = $this->clock->now()->getTimestamp();
        $policy = $point->policy();
        foreach ($actors as $actor) {
            $this->db->insert('?_security_events', [
                'detection_point' => $point->value, 'actor_key' => $actor->value, 'created_at' => $now,
            ]);
            $count = (int) $this->db->selectCell(
                'SELECT COUNT(*) FROM ?_security_events WHERE detection_point = ? AND actor_key = ? AND created_at > ?',
                $point->value, $actor->value, $now - $policy['window'],
            );
            $this->log->notice('appsensor.event', ['dp' => $point->value, 'actor' => $actor->value, 'count' => $count]);
            if ($count >= $policy['threshold']) {
                $this->respond($policy['response'], $actor, $now + $policy['duration'], $point);
            }
        }
    }

    public function isActive(ResponseAction $action, ActorKey $actor): bool
    {
        $until = $this->db->selectCell(
            'SELECT until_ts FROM ?_security_responses WHERE actor_key = ? AND response = ?',
            $actor->value, $action->value,
        );
        return $until !== null && (int) $until > $this->clock->now()->getTimestamp();
    }

    public function clear(ActorKey $actor): void
    {
        $this->db->delete('?_security_responses', ['actor_key' => $actor->value]);
        $this->db->delete('?_security_events', ['actor_key' => $actor->value]);
    }

    private function respond(ResponseAction $action, ActorKey $actor, int $until, DetectionPoint $point): void
    {
        $this->log->warning('appsensor.response', ['dp' => $point->value, 'action' => $action->value, 'actor' => $actor->value]);
        if (in_array($action, [ResponseAction::Throttle, ResponseAction::TemporaryLock, ResponseAction::Logout], true)) {
            $this->db->delete('?_security_responses', ['actor_key' => $actor->value, 'response' => $action->value]);
            $this->db->insert('?_security_responses', [
                'actor_key' => $actor->value, 'response' => $action->value, 'until_ts' => $until,
            ]);
        }
    }
}
