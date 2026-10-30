<?php
declare(strict_types=1);

namespace Bastion\Http\Controller;

use Bastion\Audit\Domain\AuditEntry;
use Bastion\Audit\Infrastructure\HmacAuditTrail;
use Bastion\Http\Middleware\RequireStaff;
use Bastion\Http\View;
use Bastion\IdentityAccess\Domain\{Account, Capability};
use Bastion\SecurityMonitoring\Domain\{ActorKey, AppSensor, DetectionPoint};
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};
use Psr\Http\Message\{ResponseInterface, ServerRequestInterface};

/**
 * Журнал аудита в админке — только чтение. Маршрутов изменения или удаления нет,
 * а у HmacAuditTrail нет методов удаления.
 */
#[AssetId('bastion-app')]
#[AbuserStory('audit-ui-wipe')]
#[Mitigation(cwe: 'CWE-284', description: 'Audit trail is append-only by API: no delete/update methods or routes; viewing requires security.view (Admin)')]
final class AuditController
{
    public function __construct(private readonly HmacAuditTrail $trail, private readonly View $view, private readonly AppSensor $sensor)
    {
    }

    public function index(ServerRequestInterface $request): ResponseInterface
    {
        $account = $request->getAttribute(RequireStaff::ACCOUNT);
        if (!$account instanceof Account || !$account->role->can(Capability::SecurityView)) {
            if ($account instanceof Account) {
                $this->sensor->event(DetectionPoint::ACE3, ActorKey::account($account->getId()));
            }
            return $this->view->admin($request, 'forbidden', [], 403);
        }
        $verification = $this->trail->verify();
        return $this->view->admin($request, 'audit', [
            'intact' => $verification->intact,
            'reason' => $verification->reason,
            'count' => (string) $verification->entries,
            'entries' => array_map(static fn (AuditEntry $e) => [
                'seq' => (string) $e->seq, 'at' => gmdate('Y-m-d H:i:s', $e->at) . ' UTC', 'action' => $e->action->value,
                'actor' => $e->actor ?? '—', 'subject' => $e->subject ?? '—', 'ip' => $e->ip,
            ], $this->trail->latest(200)),
        ]);
    }
}
