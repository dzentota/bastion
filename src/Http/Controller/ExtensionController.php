<?php
declare(strict_types=1);

namespace Bastion\Http\Controller;

use Bastion\Extensions\Application\ExtensionInstaller;
use Bastion\Extensions\Domain\{ExtCapability, ExtensionName, InstalledExtension, InvalidPackage};
use Bastion\Extensions\Infrastructure\ExtensionRegistry;
use Bastion\Extensions\Application\PackageReader;
use Bastion\Http\Middleware\RequireStaff;
use Bastion\Http\View;
use Bastion\IdentityAccess\Domain\{Account, Capability};
use Bastion\SecurityMonitoring\Domain\{ActorKey, AppSensor, DetectionPoint};
use Psr\Http\Message\{ResponseInterface, ServerRequestInterface, UploadedFileInterface};

/** Админка расширений: только Admin (settings.manage). Ничего из пакета не исполняется при установке. */
final class ExtensionController
{
    public function __construct(
        private readonly ExtensionInstaller $installer,
        private readonly ExtensionRegistry $registry,
        private readonly View $view,
        private readonly AppSensor $sensor,
    ) {
    }

    public function index(ServerRequestInterface $request, ?string $error = null, ?string $notice = null, int $status = 200): ResponseInterface
    {
        if (($deny = $this->guard($request)) !== null) {
            return $deny;
        }
        return $this->view->admin($request, 'extensions', [
            'error' => $error,
            'notice' => $notice,
            'items' => array_map(static fn (InstalledExtension $e) => [
                'name' => $e->manifest->name, 'version' => $e->manifest->version, 'enabled' => $e->enabled,
                'fingerprint' => $e->manifest->publisher->fingerprint(),
                'caps' => array_map(static fn (ExtCapability $c) => ['id' => $c->value, 'text' => $c->describe()], $e->manifest->capabilities),
                'path' => $e->manifest->name->toNative(),
            ], $this->registry->all()),
        ], $status);
    }

    public function upload(ServerRequestInterface $request): ResponseInterface
    {
        if (($deny = $this->guard($request)) !== null) {
            return $deny;
        }
        $files = $request->getUploadedFiles();
        $pkg = $files['package'] ?? null;
        $sig = $files['signature'] ?? null;
        if (!$pkg instanceof UploadedFileInterface || !$sig instanceof UploadedFileInterface
            || $pkg->getError() !== UPLOAD_ERR_OK || $sig->getError() !== UPLOAD_ERR_OK
            || ($pkg->getSize() ?? PHP_INT_MAX) > PackageReader::MAX_ARCHIVE || ($sig->getSize() ?? PHP_INT_MAX) > 1024) {
            return $this->index($request, 'Choose the package (.zip) and its signature (.sig).', null, 422);
        }
        try {
            $ext = $this->installer->install(
                $pkg->getStream()->read(PackageReader::MAX_ARCHIVE + 1), $sig->getStream()->read(1025),
                $this->account($request)->getId(), $this->ip($request),
            );
        } catch (InvalidPackage $e) {
            $this->sensor->event(DetectionPoint::IE2, ActorKey::account($this->account($request)->getId()));
            return $this->index($request, $e->getMessage(), null, 422);
        }
        return $this->index($request, null, sprintf(
            'Installed %s %s. Compare the publisher fingerprint with the one on the publisher\'s website before enabling.',
            $ext->manifest->name->toNative(), $ext->manifest->version->toNative(),
        ));
    }

    public function enable(ServerRequestInterface $request): ResponseInterface
    {
        return $this->toggle($request, true);
    }

    public function disable(ServerRequestInterface $request): ResponseInterface
    {
        return $this->toggle($request, false);
    }

    private function toggle(ServerRequestInterface $request, bool $on): ResponseInterface
    {
        if (($deny = $this->guard($request)) !== null) {
            return $deny;
        }
        $name = ExtensionName::tryParse(Input::string($request, 'name', 80), $n) ? $n : null;
        $ok = $name !== null && ($on
            ? $this->installer->enable($name, $this->account($request)->getId(), $this->ip($request))
            : $this->installer->disable($name, $this->account($request)->getId(), $this->ip($request)));
        return $ok ? $this->view->redirect('/admin/extensions') : $this->view->admin($request, 'not-found', [], 404);
    }

    private function guard(ServerRequestInterface $request): ?ResponseInterface
    {
        $account = $this->account($request);
        if ($account->role->can(Capability::SettingsManage)) {
            return null;
        }
        $this->sensor->event(DetectionPoint::ACE3, ActorKey::account($account->getId()));
        return $this->view->admin($request, 'forbidden', [], 403);
    }

    private function account(ServerRequestInterface $request): Account
    {
        $a = $request->getAttribute(RequireStaff::ACCOUNT);
        return $a instanceof Account ? $a : throw new \LogicException('RequireStaff middleware missing');
    }

    private function ip(ServerRequestInterface $request): string
    {
        $ip = $request->getServerParams()['REMOTE_ADDR'] ?? '';
        return is_string($ip) ? $ip : '';
    }
}
