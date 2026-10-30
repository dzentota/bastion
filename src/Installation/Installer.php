<?php
declare(strict_types=1);

namespace Bastion\Installation;

use Bastion\IdentityAccess\Domain\{NewPassword, Role, Username};
use Bastion\IdentityAccess\Infrastructure\AccountRepository;
use Bastion\Infrastructure\Database\{Connection, Schema};
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
     */
    public function install(array $db, Username $admin, NewPassword $password): void
    {
        if ($this->paths->isInstalled()) {
            throw new \LogicException('Already installed');
        }
        foreach (['keys', 'cache/templates', 'log'] as $dir) {
            $this->mkdir($this->paths->var($dir));
        }

        $config = ['db' => ['driver' => $db['driver']->toNative()]];
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

        Schema::migrate($conn, $db['driver']->toNative());
        $encKey = KeyFactory::generateEncryptionKey();
        KeyFactory::save($encKey, $this->paths->encryptionKey());
        @chmod($this->paths->encryptionKey(), 0600);
        $this->writeSecret($this->paths->cacheKey(), random_bytes(32));

        $accounts = new AccountRepository($conn, $encKey);
        if ($accounts->count() > 0) {
            throw new \LogicException('Database already contains accounts');
        }
        $accounts->create($admin, $password, Role::Admin);

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
