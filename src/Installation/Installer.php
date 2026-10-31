<?php
declare(strict_types=1);

namespace Bastion\Installation;

use Bastion\IdentityAccess\Domain\{NewPassword, Role, SiteUrl, StaffEmail, Username};
use Bastion\IdentityAccess\Infrastructure\AccountRepository;
use Bastion\Content\Domain\SiteLanguages;
use Bastion\Infrastructure\Database\Connection;
use Bastion\Infrastructure\Database\Migrations\{Catalog, Migrator};
use Bastion\Audit\Domain\AuditAction;
use Bastion\Audit\Infrastructure\HmacAuditTrail;
use Bastion\Media\Infrastructure\S3Config;
use Bastion\Shared\Infrastructure\SystemClock;
use ParagonIE\Halite\KeyFactory;
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};

/**
 * Веб-установщик (ADR-0002). Abuser stories: hijack-installer, reinstall-over-live.
 *
 * Защита от захвата свежей установки: при первом заходе генерируется var/install.token;
 * установить систему может только тот, кто прочитал этот файл через FTP/файловый менеджер
 * хостинга, т.е. владелец. После установки — installed.lock, установщик отвечает 404.
 */
#[AssetId('installer')]
final class Installer
{
    public function __construct(private readonly Paths $paths)
    {
    }

    public function ensureToken(): void
    {
        if ($this->paths->isInstalled() || is_file($this->paths->installToken())) {
            return;
        }
        $this->mkdir($this->paths->var());
        $this->writeSecret($this->paths->installToken(), bin2hex(random_bytes(16)) . "\n");
    }

    #[AbuserStory('hijack-installer')]
    #[Mitigation(cwe: 'CWE-306', description: 'Installation requires a one-time token readable only through hosting file access')]
    public function tokenMatches(string $submitted): bool
    {
        $file = $this->paths->installToken();
        if (!is_file($file)) {
            return false;
        }
        return hash_equals(trim((string) file_get_contents($file)), trim($submitted));
    }

    /**
     * @param array{driver: DbDriver, host?: DbHost, port?: int, name?: DbName, user?: DbName, password?: string} $db
     * @param array{host: string, port: int, user: string, password: string, from: string}|null $smtp
     */
    public function install(array $db, Username $admin, NewPassword $password, StaffEmail $email, SiteUrl $site, ?S3Config $s3 = null, ?array $smtp = null, string $ip = 'unknown', ?SiteLanguages $languages = null): void
    {
        if ($this->paths->isInstalled()) {
            throw new \LogicException('Already installed');
        }
        foreach (['keys', 'cache/templates', 'log'] as $dir) {
            $this->mkdir($this->paths->var($dir));
        }

        $config = ['db' => ['driver' => $db['driver']->toNative()]];
        $languages ??= SiteLanguages::fromConfig(null, null);
        $config['site'] = ['url' => $site->toNative(), 'languages' => $languages->codes(), 'default_language' => $languages->default->toNative()];
        if ($smtp !== null) {
            $config['mail'] = $smtp;
        }
        $config['media'] = $s3 === null ? ['driver' => 'local'] : [
            'driver' => 's3', 'endpoint' => $s3->endpoint, 'region' => $s3->region, 'bucket' => $s3->bucket,
            'access_key' => $s3->accessKey, 'secret_key' => $s3->secretKey(),
        ];
        if ($db['driver']->toNative() === 'mysql') {
            $config['db'] += [
                'host' => $db['host']->toNative(), 'port' => $db['port'], 'name' => $db['name']->toNative(),
                'user' => $db['user']->toNative(), 'password' => $db['password'],
            ];
            $conn = Connection::mysql($db['host']->toNative(), $db['port'], $db['name']->toNative(), $db['user']->toNative(), $db['password']);
        } else {
            $conn = Connection::sqlite($this->paths->sqlite());
            @chmod($this->paths->sqlite(), 0600);
        }

        (new Migrator($conn, $db['driver']->toNative(), $this->paths->migrationLock(), Catalog::all($languages->default->toNative())))->migrate(null, $ip);
        $encKey = KeyFactory::generateEncryptionKey();
        KeyFactory::save($encKey, $this->paths->encryptionKey());
        @chmod($this->paths->encryptionKey(), 0600);
        $this->writeSecret($this->paths->cacheKey(), random_bytes(32));

        $accounts = new AccountRepository($conn, $encKey);
        if ($accounts->count() > 0) {
            throw new \LogicException('Database already contains accounts');
        }
        $owner = $accounts->create($admin, $password, Role::Admin, $email);
        (new HmacAuditTrail($conn, hash_hmac('sha256', 'bastion:audit', (string) file_get_contents($this->paths->cacheKey()), true), $this->paths->auditAnchor(), new SystemClock()))
            ->record(AuditAction::Installed, $owner->getId(), null, $ip);

        $this->writeSecret($this->paths->config(), json_encode($config, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR));
        $this->writeSecret($this->paths->installedLock(), gmdate('c') . "\n");
        @unlink($this->paths->installToken());
        array_map('unlink', glob($this->paths->var('install-sessions/*')) ?: []);
        @rmdir($this->paths->var('install-sessions'));
    }

    private function mkdir(string $dir): void
    {
        if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new \RuntimeException('Cannot create directory');
        }
        if (!is_file($this->paths->var('.htaccess'))) {
            // на случай, если webroot нельзя направить в public/
            file_put_contents($this->paths->var('.htaccess'), "Require all denied\n");
        }
    }

    private function writeSecret(string $file, string $content): void
    {
        $tmp = $file . '.' . bin2hex(random_bytes(6));
        if (file_put_contents($tmp, $content, LOCK_EX) === false) {
            throw new \RuntimeException('Cannot write ' . basename($file));
        }
        chmod($tmp, 0600);
        rename($tmp, $file);
    }
}
