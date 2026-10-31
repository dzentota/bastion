<?php
declare(strict_types=1);

namespace Bastion\Http\Controller;

use Bastion\Audit\Domain\AuditTrail;
use Bastion\Http\Middleware\RequireStaff;
use Bastion\Http\View;
use Bastion\IdentityAccess\Application\TwoStepLogin;
use Bastion\IdentityAccess\Domain\{Account, Capability};
use Bastion\Infrastructure\Database\Migrations\{DatabaseBackup, Migrator, TamperedMigrations};
use Bastion\SecurityMonitoring\Domain\{ActorKey, AppSensor, DetectionPoint};
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};
use Psr\Http\Message\{ResponseInterface, ServerRequestInterface};

/** Экран «Обновить базу» (ADR-0018): единственный веб-путь, меняющий схему. */
#[AssetId('schema-migrator')]
final class DatabaseController
{
    public function __construct(
        private readonly Migrator $migrator,
        private readonly DatabaseBackup $backup,
        private readonly TwoStepLogin $login,
        private readonly View $view,
        private readonly AppSensor $sensor,
        private readonly AuditTrail $audit,
    ) {
    }

    public function show(ServerRequestInterface $request): ResponseInterface
    {
        $account = $this->admin($request);
        if ($account === null) {
            return $this->forbidden($request);
        }
        return $this->page($request, null, 200);
    }

    #[AbuserStory('unauthorized-migration')]
    #[Mitigation(cwe: 'CWE-285', description: 'Only Admin (settings.manage) behind RequireStaff; other roles are refused and raise AppSensor ACE3')]
    #[Mitigation(cwe: 'CWE-352', description: 'POST only, behind the session CSRF middleware')]
    #[Mitigation(cwe: 'CWE-308', description: 'Fresh, replay-protected TOTP code required for every run, even inside a logged-in session')]
    public function apply(ServerRequestInterface $request): ResponseInterface
    {
        $account = $this->admin($request);
        if ($account === null) {
            return $this->forbidden($request);
        }
        if (!$this->login->reconfirm($request, $account, Input::string($request, 'code', 6))) {
            return $this->page($request, 'Invalid authenticator code.', 401);
        }
        $ip = $request->getServerParams()['REMOTE_ADDR'] ?? '';
        $ip = is_string($ip) ? $ip : '';
        try {
            $this->migrator->migrate($account->getId(), $ip, $this->audit, function (): void {
                $this->backup->create();
            });
        } catch (TamperedMigrations) {
            return $this->page($request, 'Refused: applied migrations do not match this release.', 409);
        }
        return $this->view->redirect('/admin/database');
    }

    private function page(ServerRequestInterface $request, ?string $error, int $status): ResponseInterface
    {
        $state = $this->migrator->state();
        return $this->view->admin($request, 'database', [
            'current' => $state->isCurrent(),
            'pending' => $state->pending,
            'tampered' => $state->tampered,
            'error' => $error,
        ], $status);
    }

    private function admin(ServerRequestInterface $request): ?Account
    {
        $account = $request->getAttribute(RequireStaff::ACCOUNT);
        if ($account instanceof Account && $account->role->can(Capability::SettingsManage)) {
            return $account;
        }
        if ($account instanceof Account) {
            $this->sensor->event(DetectionPoint::ACE3, ActorKey::account($account->getId()));
        }
        return null;
    }

    private function forbidden(ServerRequestInterface $request): ResponseInterface
    {
        return $this->view->admin($request, 'forbidden', [], 403);
    }
}
