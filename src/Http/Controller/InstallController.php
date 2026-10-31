<?php
declare(strict_types=1);

namespace Bastion\Http\Controller;

use Bastion\Http\View;
use Bastion\IdentityAccess\Domain\{NewPassword, SiteUrl, StaffEmail, Username};
use Bastion\Mail\SmtpConfig;
use Bastion\Installation\{DbDriver, DbHost, DbName, Installer};
use Bastion\Media\Domain\{MediaId, MediaKind, StorageKey};
use Bastion\Media\Infrastructure\{S3Config, S3MediaStorage};
use Bastion\Shared\Infrastructure\SystemClock;
use Dzentota\HttpClient\HttpClient;
use Nyholm\Psr7\Factory\Psr17Factory;
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
        return $this->view->admin($request, 'install', [
            's3' => ['endpoint' => Input::string($request, 's3_endpoint', 300), 'bucket' => Input::string($request, 's3_bucket', 63),
                'region' => Input::string($request, 's3_region', 32), 'access_key' => Input::string($request, 's3_access_key', 128)],'driver_mysql' => false]);
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

        $email = StaffEmail::fromInput(Input::string($request, 'email', 320));
        if ($email === null) {
            $errors[] = 'Enter a valid email for the administrator (used for password resets).';
        }
        // Канонический адрес сайта фиксируется при установке владельцем (защищено install token).
        $uri = $request->getUri();
        $site = SiteUrl::tryParse(strtolower($uri->getScheme() . '://' . $uri->getHost() . ($uri->getPort() ? ':' . $uri->getPort() : '')), $s) ? $s : null;
        if ($site === null) {
            $errors[] = 'Cannot determine the site address.';
        }
        $smtp = null;
        if (Input::string($request, 'smtp_host', 253) !== '') {
            $smtp = ['host' => Input::string($request, 'smtp_host', 253), 'port' => (int) Input::string($request, 'smtp_port', 5),
                'user' => Input::string($request, 'smtp_user', 254), 'password' => Input::string($request, 'smtp_password', 512),
                'from' => strtolower(trim(Input::string($request, 'smtp_from', 320)))];
            try {
                new SmtpConfig($smtp['host'], $smtp['port'], $smtp['user'], $smtp['password'],
                    StaffEmail::fromInput($smtp['from']) ?? throw new \InvalidArgumentException('Invalid sender email'));
            } catch (\InvalidArgumentException $e) {
                $errors[] = 'Mail: ' . $e->getMessage();
            }
        }
        $s3 = null;
        if (Input::string($request, 's3_endpoint', 300) !== '') {
            try {
                $s3 = new S3Config(
                    Input::string($request, 's3_endpoint', 300), Input::string($request, 's3_region', 32) ?: 'auto',
                    Input::string($request, 's3_bucket', 63), Input::string($request, 's3_access_key', 128), Input::string($request, 's3_secret_key', 256),
                );
                if ($errors === []) {
                    $this->probe($s3);
                }
            } catch (\InvalidArgumentException $e) {
                $errors[] = 'Storage: ' . $e->getMessage();
            } catch (\Throwable) {
                $errors[] = 'Storage: could not write a test file to the bucket. Check the endpoint, bucket and keys.';
            }
        }

        if ($errors === [] && $username !== null && $password !== null && $email !== null && $site !== null) {
            try {
                $ip = $request->getServerParams()['REMOTE_ADDR'] ?? null;
                $this->installer->install($db, $username, $password, $email, $site, $s3, $smtp, is_string($ip) ? $ip : 'unknown');
                return $this->view->redirect('/admin/login');
            } catch (\PDOException) {
                $errors[] = 'Cannot connect to the database with these settings';
            }
        }
        return $this->view->admin($request, 'install', [
            'errors' => array_values(array_filter($errors)),
            'username' => Input::string($request, 'username', 64),
            'email' => Input::string($request, 'email', 320),
            'driver_mysql' => $driver?->toNative() === 'mysql',
        ], 422);
    }

    /** Проверка доступа: запись, чтение и удаление тестового объекта через http-client (SSRF-защита). */
    private function probe(S3Config $s3): void
    {
        $f = new Psr17Factory();
        $http = HttpClient::create();
        $http->setTimeout(10);
        $storage = new S3MediaStorage($s3, $http, $f, $f, new SystemClock());
        $key = StorageKey::for(MediaId::generate(), MediaKind::Png);
        $storage->put($key, 'bastion-probe', MediaKind::Png);
        $ok = $storage->get($key) === 'bastion-probe';
        $storage->delete($key);
        if (!$ok) {
            throw new \RuntimeException('Probe mismatch');
        }
    }
}
