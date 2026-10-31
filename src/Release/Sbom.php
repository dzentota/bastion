<?php
declare(strict_types=1);

namespace Bastion\Release;

/**
 * SBOM релиза в формате CycloneDX 1.5 (ADR-0014) из composer.lock — без сторонних генераторов.
 * Зависимости вендорятся, поэтому для каждого пакета записывается SHA-256 его дерева в vendor/:
 * тот же файл служит проверкой целостности поставленного релиза (verify).
 * Вывод детерминирован: время — из SOURCE_DATE_EPOCH, серийный номер выводится из содержимого.
 */
final class Sbom
{
    /**
     * @param array<string, mixed> $lock разобранный composer.lock
     * @return array<string, mixed>
     */
    public static function generate(array $lock, string $vendorDir, string $appVersion, int $timestamp): array
    {
        $packages = array_map(self::package(...), is_array($lock['packages'] ?? null) ? array_values($lock['packages']) : []);
        $refs = [];
        foreach ($packages as $p) {
            $refs[$p['name']] = self::purl($p['name'], $p['version']);
        }
        $components = [];
        $dependencies = [['ref' => 'pkg:composer/dzentota/bastion@' . $appVersion, 'dependsOn' => array_values($refs)]];
        foreach ($packages as $p) {
            [$group, $short] = explode('/', $p['name'], 2) + [1 => ''];
            $c = ['type' => 'library', 'bom-ref' => $refs[$p['name']], 'group' => $group, 'name' => $short,
                'version' => $p['version'], 'purl' => $refs[$p['name']]];
            if ($p['licenses'] !== []) {
                $c['licenses'] = array_map(static fn (string $l) => ['license' => preg_match('/^[A-Za-z0-9.+-]+$/', $l) ? ['id' => $l] : ['name' => $l]], $p['licenses']);
            }
            $tree = self::treeHash($vendorDir . '/' . $p['name']);
            if ($tree !== null) {
                $c['hashes'] = [['alg' => 'SHA-256', 'content' => $tree]];
            }
            $ext = array_values(array_filter([
                $p['vcs'] !== null ? ['type' => 'vcs', 'url' => $p['vcs']] : null,
                $p['dist'] !== null ? ['type' => 'distribution', 'url' => $p['dist']] : null,
            ]));
            if ($ext !== []) {
                $c['externalReferences'] = $ext;
            }
            $props = [];
            if ($p['reference'] !== null) {
                $props[] = ['name' => 'bastion:vcs-reference', 'value' => $p['reference']];
            }
            if (str_starts_with($p['version'], 'dev-')) {
                // ветка, закреплённая только коммитом в lock-файле: видимый риск цепочки поставок
                $props[] = ['name' => 'bastion:unpinned-branch', 'value' => 'true'];
            }
            if ($props !== []) {
                $c['properties'] = $props;
            }
            $components[] = $c;
            $dependencies[] = ['ref' => $refs[$p['name']], 'dependsOn' => array_values(array_intersect_key($refs, array_flip($p['requires'])))];
        }
        $contentHash = is_string($lock['content-hash'] ?? null) ? $lock['content-hash'] : '';
        return [
            'bomFormat' => 'CycloneDX',
            'specVersion' => '1.5',
            'serialNumber' => 'urn:uuid:' . self::uuid($contentHash . '|' . $appVersion . '|' . json_encode($components, JSON_THROW_ON_ERROR)),
            'version' => 1,
            'metadata' => [
                'timestamp' => gmdate('Y-m-d\TH:i:s\Z', $timestamp),
                'tools' => ['components' => [['type' => 'application', 'name' => 'bastion-sbom', 'version' => '1']]],
                'component' => ['type' => 'application', 'bom-ref' => 'pkg:composer/dzentota/bastion@' . $appVersion,
                    'name' => 'bastion', 'group' => 'dzentota', 'version' => $appVersion, 'purl' => 'pkg:composer/dzentota/bastion@' . $appVersion],
                'properties' => [['name' => 'bastion:composer-content-hash', 'value' => $contentHash]],
            ],
            'components' => $components,
            'dependencies' => $dependencies,
        ];
    }

    /**
     * Сверяет vendor/ с SBOM: изменённые и отсутствующие пакеты, а также лишние runtime-пакеты.
     * @param array<string, mixed> $sbom
     * @param list<string> $installedRuntime имена из vendor/composer/installed.json без dev-пакетов
     * @return list<string> проблемы; пусто — дерево совпадает
     */
    public static function verify(array $sbom, string $vendorDir, array $installedRuntime): array
    {
        if (($sbom['bomFormat'] ?? null) !== 'CycloneDX' || !is_array($sbom['components'] ?? null)) {
            return ['Not a CycloneDX SBOM'];
        }
        $problems = [];
        $listed = [];
        foreach ($sbom['components'] as $c) {
            if (!is_array($c) || !is_string($c['group'] ?? null) || !is_string($c['name'] ?? null)) {
                $problems[] = 'Malformed component';
                continue;
            }
            $name = $c['group'] . '/' . $c['name'];
            $listed[] = $name;
            $hash = is_array($c['hashes'] ?? null) ? ($c['hashes'][0] ?? null) : null;
            $expected = is_array($hash) && is_string($hash['content'] ?? null) ? $hash['content'] : null;
            if ($expected === null) {
                $problems[] = "{$name}: no hash in SBOM";
                continue;
            }
            $actual = self::treeHash($vendorDir . '/' . $name);
            if ($actual === null) {
                $problems[] = "{$name}: missing from vendor/";
            } elseif (!hash_equals($expected, $actual)) {
                $problems[] = "{$name}: files differ from the release (modified vendor code)";
            }
        }
        foreach (array_diff($installedRuntime, $listed) as $extra) {
            $problems[] = "{$extra}: installed but not in SBOM";
        }
        return $problems;
    }

    /** SHA-256 над отсортированным списком «путь\0sha256(файла)»; ссылки учитываются как ссылки. */
    public static function treeHash(string $dir): ?string
    {
        if (!is_dir($dir) || is_link($dir)) {
            return null;
        }
        $lines = [];
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS));
        foreach ($it as $f) {
            /** @var \SplFileInfo $f */
            $rel = substr($f->getPathname(), strlen($dir) + 1);
            $lines[] = $rel . "\0" . ($f->isLink() ? 'link:' . (string) readlink($f->getPathname()) : (string) hash_file('sha256', $f->getPathname()));
        }
        sort($lines, SORT_STRING);
        return hash('sha256', implode("\n", $lines));
    }

    /**
     * Запись composer.lock, разобранная в строгие типы.
     * @return array{name: string, version: string, licenses: list<string>, vcs: ?string, dist: ?string, reference: ?string, requires: list<string>}
     */
    private static function package(mixed $p): array
    {
        if (!is_array($p) || !is_string($p['name'] ?? null) || !is_string($p['version'] ?? null)) {
            throw new \UnexpectedValueException('composer.lock: package without name or version');
        }
        $str = static fn (mixed $v, string $k): ?string => is_array($v) && is_string($v[$k] ?? null) ? $v[$k] : null;
        return [
            'name' => $p['name'],
            'version' => $p['version'],
            'licenses' => array_values(array_filter(is_array($p['license'] ?? null) ? $p['license'] : [], 'is_string')),
            'vcs' => $str($p['source'] ?? null, 'url'),
            'dist' => $str($p['dist'] ?? null, 'url'),
            'reference' => $str($p['source'] ?? null, 'reference'),
            'requires' => is_array($p['require'] ?? null) ? array_values(array_filter(array_keys($p['require']), 'is_string')) : [],
        ];
    }

    private static function purl(string $name, string $version): string
    {
        return 'pkg:composer/' . implode('/', array_map('rawurlencode', explode('/', $name))) . '@' . rawurlencode($version);
    }

    private static function uuid(string $seed): string
    {
        $h = substr(hash('sha256', $seed), 0, 32);
        $h[12] = '5';
        $h[16] = dechex((hexdec($h[16]) & 0x3) | 0x8);
        return substr($h, 0, 8) . '-' . substr($h, 8, 4) . '-' . substr($h, 12, 4) . '-' . substr($h, 16, 4) . '-' . substr($h, 20, 12);
    }
}
