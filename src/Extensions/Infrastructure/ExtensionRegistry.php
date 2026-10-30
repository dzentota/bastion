<?php
declare(strict_types=1);

namespace Bastion\Extensions\Infrastructure;

use Bastion\Extensions\Domain\{ExtCapability, ExtensionName, InstalledExtension, Manifest};
use Bastion\Infrastructure\Database\Row;
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};
use SecureDb\Db;

/**
 * Реестр установленных расширений. Каждая строка подписана HMAC ключом вне БД:
 * доступ к БД не позволяет включить расширение, выдать ему права, подменить хэши файлов
 * или закреплённый ключ издателя — такая строка просто не загрузится.
 */
#[AssetId('bastion-app')]
#[AbuserStory('extension-key-substitution')]
#[Mitigation(cwe: 'CWE-347', description: 'Publisher key pinned on first install (admin compares fingerprint); later versions must be signed by the same key; registry rows HMAC-protected')]
final class ExtensionRegistry
{
    public function __construct(private readonly Db $db, #[\SensitiveParameter] private readonly string $key)
    {
    }

    public function save(InstalledExtension $e, string $manifestJson): void
    {
        $row = [
            'name' => $e->manifest->name->toNative(),
            'manifest' => $manifestJson,
            'files' => json_encode($e->fileHashes, JSON_THROW_ON_ERROR),
            'granted' => json_encode(array_map(static fn (ExtCapability $c) => $c->value, $e->granted), JSON_THROW_ON_ERROR),
            'enabled' => $e->enabled ? 1 : 0,
        ];
        $row['mac'] = $this->mac($row);
        $this->db->tryFlatTransaction(function (Db $db) use ($row): void {
            $db->delete('?_extensions', ['name' => $row['name']]);
            $db->insert('?_extensions', $row);
        });
    }

    public function find(ExtensionName $name): ?InstalledExtension
    {
        $row = $this->db->selectRow('SELECT * FROM ?_extensions WHERE name = ?', $name->toNative());
        return $row ? $this->hydrate(Row::of($row)) : null;
    }

    /** @return list<InstalledExtension> строки с неверной подписью пропускаются */
    public function all(): array
    {
        $out = [];
        foreach ($this->db->select('SELECT * FROM ?_extensions ORDER BY name') as $raw) {
            $e = $this->hydrate(Row::of($raw));
            if ($e !== null) {
                $out[] = $e;
            }
        }
        return $out;
    }

    public function manifestJson(ExtensionName $name): ?string
    {
        $v = $this->db->selectCell('SELECT manifest FROM ?_extensions WHERE name = ?', $name->toNative());
        return is_string($v) ? $v : null;
    }

    private function hydrate(Row $r): ?InstalledExtension
    {
        $row = ['name' => $r->str('name'), 'manifest' => $r->str('manifest'), 'files' => $r->str('files'),
            'granted' => $r->str('granted'), 'enabled' => $r->int('enabled')];
        if (!hash_equals($this->mac($row), $r->str('mac'))) {
            return null; // подделка или повреждение — не загружаем
        }
        $files = [];
        foreach ((array) json_decode($row['files'], true, 3, JSON_THROW_ON_ERROR) as $path => $hash) {
            if (is_string($path) && is_string($hash)) {
                $files[$path] = $hash;
            }
        }
        $granted = [];
        foreach ((array) json_decode($row['granted'], true, 3, JSON_THROW_ON_ERROR) as $c) {
            $cap = is_string($c) ? ExtCapability::tryFrom($c) : null;
            if ($cap !== null) {
                $granted[] = $cap;
            }
        }
        return new InstalledExtension(
            Manifest::parse($row['manifest']),
            $files,
            $granted,
            $row['enabled'] === 1,
        );
    }

    /** @param array{name: string, manifest: string, files: string, granted: string, enabled: int} $row */
    private function mac(array $row): string
    {
        return hash_hmac('sha256', json_encode([$row['name'], $row['manifest'], $row['files'], $row['granted'], $row['enabled']], JSON_THROW_ON_ERROR), $this->key);
    }
}
