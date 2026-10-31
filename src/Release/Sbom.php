<?php
declare(strict_types=1);

namespace Bastion\Release;

/**
 * SBOM релиза в формате CycloneDX 1.5 (ADR-0014) из composer.lock — без сторонних генераторов.
 * Зависимости вендорятся, поэтому для каждого пакета записывается SHA-256 его дерева в vendor/:
 * тот же файл служит проверкой целостности поставленного релиза (verify).
 * Вывод детерминирован: время — из SOURCE_DATE_EPOCH, серийный номер выводится из содержимого.
 */
#[\HybridTM\Attributes\AssetId('app-filesystem')]
#[\HybridTM\Attributes\AbuserStory('vendored-asset-tamper')]
#[\HybridTM\Attributes\AbuserStory('threat-model-export-tamper')]
#[\HybridTM\Attributes\Mitigation(cwe: 'CWE-494', description: 'Vendored fonts are pinned to an exact package version, self-hosted and listed in the SBOM with a SHA-256 over their files; the SBOM also records the SHA-256 of build/threat-model.json; bin/sbom verify detects a swapped or missing file')]
final class Sbom
{
    /** Вендорные статические ресурсы (шрифты): манифест рядом с файлами, путь от корня релиза. */
    public const ASSET_MANIFESTS = ['public/assets/fonts/fonts.json'];
    public const THREAT_MODEL = 'build/threat-model.json';

    /**
     * @param array<string, mixed> $lock разобранный composer.lock
     * @param string|null $root корень релиза: если задан, в SBOM попадают и ресурсы из ASSET_MANIFESTS
     * @return array<string, mixed>
     */
    public static function generate(array $lock, string $vendorDir, string $appVersion, int $timestamp, ?string $root = null): array
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
        foreach ($root !== null ? self::assets($root) : [] as $a) {
            $components[] = [
                'type' => 'library', 'bom-ref' => $a['purl'], 'group' => $a['group'], 'name' => $a['name'], 'version' => $a['version'],
                'purl' => $a['purl'], 'licenses' => [['license' => ['id' => $a['license']]]],
                'hashes' => [['alg' => 'SHA-256', 'content' => self::filesHash($root . '/' . $a['path'], $a['files']) ?? '']],
                'externalReferences' => [['type' => 'distribution', 'url' => $a['source']]],
                'properties' => [['name' => 'bastion:asset-path', 'value' => $a['path']], ['name' => 'bastion:asset-files', 'value' => implode(',', $a['files'])]],
            ];
            $dependencies[0]['dependsOn'][] = $a['purl'];
        }
        $contentHash = is_string($lock['content-hash'] ?? null) ? $lock['content-hash'] : '';
        $metaProps = [['name' => 'bastion:composer-content-hash', 'value' => $contentHash]];
        if ($root !== null && is_file($root . '/' . self::THREAT_MODEL)) {
            // экспорт модели угроз для сайта документации (ADR-0023): его подмену ловит verify
            $metaProps[] = ['name' => 'bastion:threat-model-sha256', 'value' => (string) hash_file('sha256', $root . '/' . self::THREAT_MODEL)];
        }
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
                'properties' => $metaProps,
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
    public static function verify(array $sbom, string $vendorDir, array $installedRuntime, ?string $root = null): array
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
            $asset = self::assetProperties($c);
            if ($asset !== null) {
                // ресурс (шрифт) — не пакет vendor/
                $actual = $root !== null ? self::filesHash($root . '/' . $asset[0], $asset[1]) : null;
                if ($actual === null || !hash_equals($expected, $actual)) {
                    $problems[] = "{$name}: asset files differ from the release";
                }
                continue;
            }
            $actual = self::treeHash($vendorDir . '/' . $name);
            if ($actual === null) {
                $problems[] = "{$name}: missing from vendor/";
            } elseif (!hash_equals($expected, $actual)) {
                $problems[] = "{$name}: files differ from the release (modified vendor code)";
            }
        }
        $meta = is_array($sbom['metadata'] ?? null) ? $sbom['metadata'] : [];
        foreach (is_array($meta['properties'] ?? null) ? $meta['properties'] : [] as $p) {
            if (is_array($p) && ($p['name'] ?? null) === 'bastion:threat-model-sha256' && is_string($p['value'] ?? null)) {
                $file = $root !== null ? $root . '/' . self::THREAT_MODEL : null;
                if ($file === null || !is_file($file) || !hash_equals($p['value'], (string) hash_file('sha256', $file))) {
                    $problems[] = self::THREAT_MODEL . ': differs from the release';
                }
            }
        }
        foreach (array_diff($installedRuntime, $listed) as $extra) {
            $problems[] = "{$extra}: installed but not in SBOM";
        }
        return $problems;
    }

    /**
     * Хэш набора файлов каталога в том же формате, что treeHash. Лишние файлы в каталоге не учитываются,
     * отсутствующий или символическая ссылка — null.
     * @param list<string> $files
     */
    public static function filesHash(string $dir, array $files): ?string
    {
        $lines = [];
        foreach ($files as $f) {
            $path = $dir . '/' . $f;
            if (!preg_match('/^[A-Za-z0-9._-]+$/', $f) || !is_file($path) || is_link($path)) {
                return null;
            }
            $lines[] = $f . "\0" . (string) hash_file('sha256', $path);
        }
        sort($lines, SORT_STRING);
        return hash('sha256', implode("\n", $lines));
    }

    /** @return list<array{purl: string, group: string, name: string, version: string, license: string, source: string, path: string, files: list<string>}> */
    private static function assets(string $root): array
    {
        $out = [];
        foreach (self::ASSET_MANIFESTS as $manifest) {
            $data = json_decode((string) file_get_contents($root . '/' . $manifest), true, 4, JSON_THROW_ON_ERROR);
            foreach (is_array($data) ? $data : [] as $a) {
                if (!is_array($a)) {
                    continue;
                }
                $s = static fn (string $k): string => is_string($a[$k] ?? null) ? $a[$k] : throw new \UnexpectedValueException("{$manifest}: {$k}");
                $files = array_values(array_filter(is_array($a['files'] ?? null) ? $a['files'] : [], 'is_string'));
                $out[] = ['purl' => $s('purl'), 'group' => $s('group'), 'name' => $s('name'), 'version' => $s('version'), 'license' => $s('license'),
                    'source' => $s('source'), 'path' => dirname($manifest), 'files' => $files];
            }
        }
        return $out;
    }

    /**
     * @param array<mixed> $c
     * @return array{0: string, 1: list<string>}|null
     */
    private static function assetProperties(array $c): ?array
    {
        $path = $files = null;
        foreach (is_array($c['properties'] ?? null) ? $c['properties'] : [] as $p) {
            if (is_array($p) && ($p['name'] ?? null) === 'bastion:asset-path' && is_string($p['value'] ?? null)) {
                $path = $p['value'];
            }
            if (is_array($p) && ($p['name'] ?? null) === 'bastion:asset-files' && is_string($p['value'] ?? null)) {
                $files = explode(',', $p['value']);
            }
        }
        return $path !== null && $files !== null && !str_contains($path, '..') ? [$path, $files] : null;
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
