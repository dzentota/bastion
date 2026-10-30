<?php
declare(strict_types=1);

namespace Bastion\Http\Controller;

use Bastion\Http\View;
use Bastion\IdentityAccess\Domain\{NewPassword, Username};
use Bastion\Installation\{DbDriver, DbHost, DbName, Installer};
use Bastion\SecurityMonitoring\Domain\{ActorKey, AppSensor, DetectionPoint};
use Psr\Http\Message\{ResponseInterface, ServerRequestInterface};

final class InstallController
{
    public function __construct(private readonly Installer $installer, private readonly View $view, private readonly AppSensor $sensor)
    {
    }

    public function form(ServerRequestInterface $request): ResponseInterface
    {
        $this->installer->ensureToken();
        return $this->view->admin($request, 'install', ['driver_mysql' => false]);
    }

    public function submit(ServerRequestInterface $request): ResponseInterface
    {
        $errors = [];
        if (!$this->installer->tokenMatches(Input::string($request, 'install_token', 64))) {
            $this->sensor->event(DetectionPoint::STE1, ActorKey::ip((string) ($request->getServerParams()['REMOTE_ADDR'] ?? '')));
            $errors[] = 'Install token does not match var/install.token';
        }
        $username = Username::tryParse(Input::string($request, 'username', 64), $u, $res) ? $u : null;
        if ($username === null) {
            $errors[] = $res->getFirstError()?->getMessage();
        }
        $password = $username ? NewPassword::forUser(Input::string($request, 'password', 1024), $username, $pres) : null;
        if ($username && $password === null) {
            $errors[] = $pres->getFirstError()?->getMessage();
        }
        $driver = DbDriver::tryParse(Input::string($request, 'driver', 8), $d) ? $d : null;
        $db = ['driver' => $driver ?? DbDriver::fromNative('sqlite')];
        if ($driver?->toNative() === 'mysql') {
            $port = (int) Input::string($request, 'db_port', 5);
            if (!DbHost::tryParse(Input::string($request, 'db_host', 253), $host) || !DbName::tryParse(Input::string($request, 'db_name', 64), $name)
                || !DbName::tryParse(Input::string($request, 'db_user', 64), $user) || $port < 1 || $port > 65535) {
                $errors[] = 'Invalid MySQL settings';
            } else {
                $db += ['host' => $host, 'port' => $port, 'name' => $name, 'user' => $user, 'password' => Input::string($request, 'db_password', 512)];
            }
        } elseif ($driver === null) {
            $errors[] = 'Choose a database driver';
        }

        if ($errors === []) {
            try {
                $this->installer->install($db, $username, $password);
                return $this->view->redirect('/admin/login');
            } catch (\PDOException) {
                $errors[] = 'Cannot connect to the database with these settings';
            }
        }
        return $this->view->admin($request, 'install', [
            'errors' => array_values(array_filter($errors)),
            'username' => Input::string($request, 'username', 64),
            'driver_mysql' => $driver?->toNative() === 'mysql',
        ], 422);
    }
}
