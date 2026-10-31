<?php
declare(strict_types=1);

namespace Bastion\Http\Controller;

use Bastion\Http\Middleware\RequireStaff;
use Bastion\Http\View;
use Bastion\IdentityAccess\Domain\Account;
use Bastion\IdentityAccess\Infrastructure\AccountRepository;
use Bastion\Shared\I18n\StringCatalog;
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};
use Psr\Http\Message\{ResponseInterface, ServerRequestInterface};

/** Личные настройки сотрудника: пока только язык интерфейса админки. */
#[AssetId('bastion-app')]
final class PreferencesController
{
    public function __construct(
        private readonly AccountRepository $accounts,
        private readonly StringCatalog $catalog,
        private readonly View $view,
    ) {
    }

    #[AbuserStory('ui-locale-tampering')]
    #[Mitigation(cwe: 'CWE-20', description: 'Only languages with an admin catalog are stored; staff-only route behind CSRF; the setting changes only the caller\'s own account')]
    #[Mitigation(cwe: 'CWE-601', description: 'Always redirects to the fixed /admin path, never to a request-supplied return URL')]
    public function locale(ServerRequestInterface $request): ResponseInterface
    {
        $account = $request->getAttribute(RequireStaff::ACCOUNT);
        $code = Input::string($request, 'lang', 8);
        foreach ($this->catalog->adminLanguages() as $lang) {
            if ($account instanceof Account && $lang->toNative() === $code) {
                $this->accounts->setLocale($account->id, $lang);
            }
        }
        // всегда в админку: адрес возврата из запроса стал бы open redirect
        return $this->view->redirect('/admin');
    }
}
