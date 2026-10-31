<?php
declare(strict_types=1);

namespace Bastion\Extensions\Application;

use Bastion\Audit\Domain\{AuditAction, AuditTrail};
use Bastion\Extensions\Domain\{ExtCapability, ExtensionName, InstalledExtension, InvalidPackage};
use Bastion\Extensions\Infrastructure\ExtensionRegistry;

/**
 * Установка: подпись → закреплённый ключ → журнал обновлений (если настроен) → чтение архива → Static Gate → атомарная запись → реестр.
 * Ничего из пакета не исполняется при установке (в отличие от install-триггеров Airship).
 * Новая версия устанавливается выключенной, если просит новые права; иначе сохраняет выданные.
 */
final class ExtensionInstaller
{
    public function __construct(
        private readonly PackageReader $reader,
        private readonly StaticGate $gate,
        private readonly ExtensionRegistry $registry,
        private readonly string $extensionsDir,
        private readonly AuditTrail $audit,
        private readonly ?ReleaseAttestor $attestor = null,
    ) {
    }

    /** @throws InvalidPackage */
    public function install(string $zipBytes, string $signature, string $actor, string $ip): InstalledExtension
    {
        $package = $this->reader->read($zipBytes);
        $m = $package->manifest;
        if (!PackageSignature::verify($zipBytes, $signature, $m->publisher)) {
            throw new InvalidPackage('Signature does not match the publisher key in the package');
        }
        $previous = $this->registry->find($m->name);
        if ($previous !== null && !hash_equals($previous->manifest->publisher->toNative(), $m->publisher->toNative())
            && !($this->attestor?->allowsRotation($previous->manifest, $m) ?? false)) {
            throw new InvalidPackage('This extension is pinned to a different publisher key. Refusing to replace it.');
        }
        $this->attestor?->attest($m, $zipBytes);
        if ($previous !== null && !$m->version->isNewerThan($previous->manifest->version)) {
            throw new InvalidPackage('Only newer versions can be installed over an existing extension');
        }
        $violations = $this->gate->check($package->phpFiles(), $m->name->namespace());
        if ($violations !== []) {
            throw new InvalidPackage("Static Gate rejected the code:\n" . implode("\n", array_slice(array_map('strval', $violations), 0, 20)));
        }

        $dir = $this->versionDir($m->name, $m->version->toNative());
        $this->writeAtomically($dir, $package->files);

        // Права сохраняются только если новая версия не просит больше, чем было выдано.
        $granted = $previous !== null ? $previous->granted : [];
        $keepEnabled = $previous?->enabled === true && array_diff($m->capabilityValues(), array_map(static fn (ExtCapability $c) => $c->value, $granted)) === [];
        $installed = new InstalledExtension($m, array_map(static fn (string $c) => hash('sha256', $c), $package->files), $keepEnabled ? $granted : [], $keepEnabled);
        $this->registry->save($installed, (string) $package->files['extension.json']);
        $this->audit->record(AuditAction::ExtensionInstalled, $actor, $this->subject($m->name), $ip);
        return $installed;
    }

    public function enable(ExtensionName $name, string $actor, string $ip): bool
    {
        $e = $this->registry->find($name);
        $json = $this->registry->manifestJson($name);
        if ($e === null || $json === null) {
            return false;
        }
        $this->registry->save(new InstalledExtension($e->manifest, $e->fileHashes, $e->manifest->capabilities, true), $json);
        $this->audit->record(AuditAction::ExtensionEnabled, $actor, $this->subject($name), $ip);
        return true;
    }

    public function disable(ExtensionName $name, string $actor, string $ip): bool
    {
        $e = $this->registry->find($name);
        $json = $this->registry->manifestJson($name);
        if ($e === null || $json === null) {
            return false;
        }
        $this->registry->save(new InstalledExtension($e->manifest, $e->fileHashes, [], false), $json);
        $this->audit->record(AuditAction::ExtensionDisabled, $actor, $this->subject($name), $ip);
        return true;
    }

    public function versionDir(ExtensionName $name, string $version): string
    {
        return $this->extensionsDir . '/' . $name->vendor() . '/' . $name->package() . '/' . $version;
    }

    private function subject(ExtensionName $name): string
    {
        return str_replace('/', ':', $name->toNative());
    }

    /** @param array<string, string> $files */
    private function writeAtomically(string $dir, array $files): void
    {
        $tmp = $dir . '.tmp-' . bin2hex(random_bytes(6));
        foreach ($files as $path => $content) {
            // путь уже проверен грамматикой PackageReader::PATH
            $target = $tmp . '/' . $path;
            if (!is_dir(dirname($target)) && !mkdir(dirname($target), 0750, true) && !is_dir(dirname($target))) {
                throw new \RuntimeException('Cannot create extension directory');
            }
            file_put_contents($target, $content, LOCK_EX);
            chmod($target, 0640);
        }
        if (is_dir($dir)) {
            throw new InvalidPackage('This version is already installed');
        }
        rename($tmp, $dir);
    }
}
