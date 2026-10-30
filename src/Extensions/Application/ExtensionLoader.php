<?php
declare(strict_types=1);

namespace Bastion\Extensions\Application;

use Bastion\Extension\Api\{ContentReader, Extension};
use Bastion\Extensions\Domain\InstalledExtension;
use Bastion\Extensions\Infrastructure\ExtensionRegistry;
use Bastion\SecurityMonitoring\Domain\{ActorKey, AppSensor, DetectionPoint};
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};
use Psr\Log\LoggerInterface;

/**
 * Загрузка включённых расширений на каждом запросе (ADR-0012).
 *
 * В отличие от Airship (подпись проверяется только при установке), здесь хэш КАЖДОГО файла
 * сверяется с подписанным HMAC реестром при каждой загрузке, а исполняются именно проверенные
 * байты (eval проверенного содержимого вместо include пути — нет TOCTOU между проверкой и исполнением).
 * Цена: код расширений не кэшируется opcache.
 */
#[AssetId('bastion-app')]
#[AbuserStory('extension-disk-tamper')]
#[Mitigation(cwe: 'CWE-345', description: 'On every load each file is hashed and compared with the HMAC-protected registry; only the verified bytes are executed; any mismatch disables the extension and raises AppSensor STE1')]
final class ExtensionLoader
{
    public function __construct(
        private readonly ExtensionRegistry $registry,
        private readonly ExtensionInstaller $installer,
        private readonly HelperCollector $helpers,
        private readonly ContentReader $content,
        private readonly AppSensor $sensor,
        private readonly LoggerInterface $log,
    ) {
    }

    /** @return list<string> имена загруженных расширений */
    public function loadEnabled(): array
    {
        $loaded = [];
        foreach ($this->registry->all() as $ext) {
            if ($ext->enabled && $this->load($ext)) {
                $loaded[] = $ext->manifest->name->toNative();
            }
        }
        return $loaded;
    }

    private function load(InstalledExtension $ext): bool
    {
        $m = $ext->manifest;
        $dir = $this->installer->versionDir($m->name, $m->version->toNative());
        $sources = [];
        foreach ($ext->fileHashes as $path => $hash) {
            if (!str_ends_with($path, '.php')) {
                continue;
            }
            $bytes = @file_get_contents($dir . '/' . $path);
            if ($bytes === false || !hash_equals($hash, hash('sha256', $bytes))) {
                $this->log->critical('extension.integrity_failed', ['extension' => $m->name->toNative(), 'file' => $path]);
                $this->sensor->event(DetectionPoint::STE1, ActorKey::ip('server'));
                return false;
            }
            $sources[$path] = $bytes;
        }

        $prefix = $m->name->namespace() . '\\';
        spl_autoload_register(static function (string $class) use ($prefix, $sources): void {
            if (!str_starts_with($class, $prefix)) {
                return;
            }
            $path = 'src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
            if (isset($sources[$path])) {
                // Исполняются ровно те байты, хэш которых только что проверен.
                eval('?>' . $sources[$path]);
            }
        });

        try {
            $class = $m->entryFqcn();
            if (!class_exists($class) || !is_subclass_of($class, Extension::class)) {
                $this->log->error('extension.bad_entry', ['extension' => $m->name->toNative()]);
                return false;
            }
            (new $class())->register(new ExtensionContext($ext, $this->helpers, $this->content, $this->log));
            return true;
        } catch (\Throwable $e) {
            $this->log->error('extension.register_failed', ['extension' => $m->name->toNative(), 'type' => $e::class, 'msg' => $e->getMessage()]);
            return false;
        }
    }
}
