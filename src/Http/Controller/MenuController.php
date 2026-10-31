<?php
declare(strict_types=1);

namespace Bastion\Http\Controller;

use Bastion\Audit\Domain\{AuditAction, AuditTrail};
use Bastion\Content\Domain\{EntryId, MenuPosition, SiteLanguages};
use Bastion\Content\Infrastructure\MenuRepository;
use Bastion\Http\Middleware\RequireStaff;
use Bastion\Http\View;
use Bastion\IdentityAccess\Domain\{Account, Capability};
use Bastion\SecurityMonitoring\Domain\{ActorKey, AppSensor, DetectionPoint};
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};
use Psr\Http\Message\{ResponseInterface, ServerRequestInterface};

/** Редактор меню сайта: порядок, удаление и добавление страниц, отдельно для каждого языка. */
#[AssetId('bastion-app')]
final class MenuController
{
    public function __construct(
        private readonly MenuRepository $menu,
        private readonly SiteLanguages $languages,
        private readonly View $view,
        private readonly AppSensor $sensor,
        private readonly AuditTrail $audit,
    ) {
    }

    public function show(ServerRequestInterface $request): ResponseInterface
    {
        if ($this->editor($request) === null) {
            return $this->view->admin($request, 'forbidden', [], 403);
        }
        $lang = $this->languages->resolve($request->getQueryParams()['lang'] ?? null) ?? $this->languages->default;
        return $this->view->admin($request, 'menu', [
            'lang' => $lang->toNative(),
            'languages' => count($this->languages->all) > 1
                ? array_map(static fn ($l) => ['code' => $l->toNative(), 'current' => $l->toNative() === $lang->toNative()], $this->languages->all) : [],
            'items' => array_map(static fn (array $i) => ['position' => (string) $i['position']] + $i, $this->menu->editable($lang)),
            'candidates' => $this->menu->candidates($lang),
            'full' => count($this->menu->editable($lang)) >= MenuRepository::MAX_ITEMS,
        ]);
    }

    #[AbuserStory('menu-tamper')]
    #[Mitigation(cwe: 'CWE-285', description: 'Menu changes require content.publish (Editor/Admin); other roles are refused with AppSensor ACE3; behind CSRF')]
    #[Mitigation(cwe: 'CWE-20', description: 'Only pages of the selected site language can be placed; positions are MenuPosition primitives; the menu is capped at MAX_ITEMS')]
    public function update(ServerRequestInterface $request): ResponseInterface
    {
        $account = $this->editor($request);
        if ($account === null) {
            return $this->view->admin($request, 'forbidden', [], 403);
        }
        $lang = $this->languages->resolve(Input::string($request, 'lang', 8));
        if ($lang === null) {
            return $this->view->redirect('/admin/menu');
        }
        $body = $request->getParsedBody();
        $positions = is_array($body) && is_array($body['position'] ?? null) ? $body['position'] : [];
        $remove = array_values(array_filter(is_array($body) && is_array($body['remove'] ?? null) ? $body['remove'] : [], 'is_string'));
        foreach (array_slice($positions, 0, 50, true) as $id => $pos) {
            if (EntryId::tryParse((string) $id, $entry) && $this->menu->isPageIn($entry, $lang)) {
                $this->menu->place($entry, in_array((string) $id, $remove, true) ? null
                    : (MenuPosition::tryParse(is_string($pos) ? $pos : '', $p) ? $p : $this->menu->positionOf($entry)));
            }
        }
        $add = Input::string($request, 'add', 36);
        $addPos = Input::string($request, 'add_position', 16) ?: '10';
        if ($add !== '' && EntryId::tryParse($add, $new) && $this->menu->isPageIn($new, $lang)
            && count($this->menu->editable($lang)) < MenuRepository::MAX_ITEMS && MenuPosition::tryParse($addPos, $p)) {
            $this->menu->place($new, $p);
        }
        $ip = $request->getServerParams()['REMOTE_ADDR'] ?? '';
        $this->audit->record(AuditAction::MenuUpdated, $account->getId(), $lang->toNative(), is_string($ip) ? $ip : '');
        return $this->view->redirect('/admin/menu?lang=' . $lang->toNative());
    }

    private function editor(ServerRequestInterface $request): ?Account
    {
        $account = $request->getAttribute(RequireStaff::ACCOUNT);
        if ($account instanceof Account && $account->role->can(Capability::ContentPublish)) {
            return $account;
        }
        if ($account instanceof Account) {
            $this->sensor->event(DetectionPoint::ACE3, ActorKey::account($account->getId()));
        }
        return null;
    }
}
