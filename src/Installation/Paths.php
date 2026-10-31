<?php
declare(strict_types=1);

namespace Bastion\Installation;

/** Раскладка файлов. Всё, кроме public/, должно быть вне webroot. */
final class Paths
{
    public function __construct(public readonly string $root)
    {
    }

    public function var(string $p = ''): string { return $this->root . '/var' . ($p === '' ? '' : '/' . $p); }
    public function config(): string { return $this->var('config.json'); }
    public function installedLock(): string { return $this->var('installed.lock'); }
    public function installToken(): string { return $this->var('install.token'); }
    public function encryptionKey(): string { return $this->var('keys/encryption.key'); }
    public function cacheKey(): string { return $this->var('keys/cache.key'); }
    public function migrationLock(): string { return $this->var('migrate.lock'); }
    public function backups(): string { return $this->var('backups'); }
    public function updateStatus(): string { return $this->var('updates.status'); }
    public function auditAnchor(): string { return $this->var('audit.anchor'); }
    public function templateCache(): string { return $this->var('cache/templates'); }
    public function sqlite(): string { return $this->var('bastion.sqlite'); }
    public function adminTemplates(): string { return $this->root . '/templates/admin'; }
    public function extensions(): string { return $this->root . '/extensions'; }
    public function theme(string $name): string { return $this->root . '/themes/' . $name . '/templates'; }

    public function isInstalled(): bool
    {
        return is_file($this->installedLock());
    }
}
