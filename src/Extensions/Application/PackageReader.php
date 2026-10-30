<?php
declare(strict_types=1);

namespace Bastion\Extensions\Application;

use Bastion\Extensions\Domain\{InvalidPackage, Manifest};
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};

/**
 * Чтение пакета расширения (ZIP) без ZipArchive::extractTo: каждая запись проверяется
 * и читается в память с ограничением размера; на диск пишет только установщик.
 */
#[AssetId('bastion-app')]
#[AbuserStory('extension-zip-slip')]
#[Mitigation(cwe: 'CWE-22', description: 'Entry names validated against a strict grammar (no .., absolute paths, backslashes, symlinks or special files); files written by the installer under computed paths only')]
#[AbuserStory('extension-archive-bomb')]
#[Mitigation(cwe: 'CWE-409', description: 'Limits on archive size, entry count, per-file and total uncompressed size, enforced while streaming entries; compression ratio capped')]
final class PackageReader
{
    public const MAX_ARCHIVE = 2 * 1024 * 1024;
    private const MAX_ENTRIES = 200;
    private const MAX_FILE = 512 * 1024;
    private const MAX_TOTAL = 4 * 1024 * 1024;
    private const MAX_RATIO = 100;
    private const PATH = '~^(extension\.json|README\.md|LICENSE|src(/[A-Za-z0-9_-]+)*/[A-Z][A-Za-z0-9]*\.php|templates(/[a-z0-9_-]+)*/[a-z0-9_-]+\.tpl)$~';

    public function read(string $zipBytes): Package
    {
        if (strlen($zipBytes) > self::MAX_ARCHIVE || !str_starts_with($zipBytes, "PK\x03\x04")) {
            throw new InvalidPackage('Package must be a ZIP archive up to 2 MB');
        }
        $tmp = tempnam(sys_get_temp_dir(), 'bext');
        if ($tmp === false) {
            throw new \RuntimeException('Cannot create temp file');
        }
        try {
            file_put_contents($tmp, $zipBytes);
            $zip = new \ZipArchive();
            if ($zip->open($tmp, \ZipArchive::RDONLY | \ZipArchive::CHECKCONS) !== true) {
                throw new InvalidPackage('Corrupt ZIP archive');
            }
            try {
                return $this->entries($zip);
            } finally {
                $zip->close();
            }
        } finally {
            @unlink($tmp);
        }
    }

    private function entries(\ZipArchive $zip): Package
    {
        if ($zip->numFiles < 1 || $zip->numFiles > self::MAX_ENTRIES) {
            throw new InvalidPackage('Too many or too few entries');
        }
        $files = [];
        $total = 0;
        for ($i = 0; $i < $zip->numFiles; $i++) {
            $stat = $zip->statIndex($i);
            $name = is_array($stat) ? $stat['name'] : '';
            if (str_ends_with($name, '/')) {
                continue; // каталоги не создаются из архива
            }
            if (!preg_match(self::PATH, $name) || isset($files[$name])) {
                throw new InvalidPackage("Disallowed entry: " . substr(preg_replace('/[^\x20-\x7E]/', '?', $name) ?? '', 0, 120));
            }
            $os = $attr = 0;
            $zip->getExternalAttributesIndex($i, $os, $attr);
            $type = is_int($attr) ? ($attr >> 16) & 0xF000 : -1;
            if ($os === \ZipArchive::OPSYS_UNIX && $type !== 0 && $type !== 0x8000) {
                throw new InvalidPackage("Symlinks and special files are not allowed: {$name}");
            }
            if ($stat['size'] > self::MAX_FILE || ($stat['comp_size'] > 0 && $stat['size'] / $stat['comp_size'] > self::MAX_RATIO)) {
                throw new InvalidPackage("Entry too large: {$name}");
            }
            $stream = $zip->getStream($name);
            $data = $stream === false ? false : stream_get_contents($stream, self::MAX_FILE + 1);
            if ($data === false || strlen($data) > self::MAX_FILE || strlen($data) !== $stat['size']) {
                throw new InvalidPackage("Cannot read entry: {$name}");
            }
            $total += strlen($data);
            if ($total > self::MAX_TOTAL) {
                throw new InvalidPackage('Package is too large when unpacked');
            }
            if (!mb_check_encoding($data, 'UTF-8')) {
                throw new InvalidPackage("Entry is not UTF-8 text: {$name}");
            }
            $files[$name] = $data;
        }
        $manifest = Manifest::parse($files['extension.json'] ?? throw new InvalidPackage('extension.json is missing'));
        if (!isset($files['src/' . $manifest->entryClass . '.php'])) {
            throw new InvalidPackage('Entry class file is missing');
        }
        return new Package($manifest, $files);
    }
}
