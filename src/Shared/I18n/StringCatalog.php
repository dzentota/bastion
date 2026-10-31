<?php
declare(strict_types=1);

namespace Bastion\Shared\I18n;

use Bastion\Content\Domain\Language;
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};

/**
 * Каталоги строк интерфейса: translations/{domain}/{lang}.json. Английский — исходный язык;
 * ключа нет в переводе — берётся английский. JSON, а не PHP: каталог — данные, не код.
 *
 * Домены: admin и theme — ключи для шаблонов ({{ t.key }}); messages — сообщения
 * контроллеров, ключ — сам английский текст.
 */
#[AssetId('bastion-app')]
#[AbuserStory('catalog-injection')]
#[Mitigation(cwe: 'CWE-94', description: 'Catalogs are JSON data, never included as PHP; only string values are accepted; templates escape translated strings like any other value')]
final class StringCatalog
{
    public const DOMAINS = ['admin', 'theme', 'messages'];
    private const MAX_BYTES = 262144;

    /** @var array<string, array<string, string>> */
    private array $loaded = [];

    public function __construct(private readonly string $dir)
    {
    }

    /** @return array<string, string> английские строки, перекрытые переводом */
    public function strings(string $domain, Language $lang): array
    {
        $base = $this->load($domain, 'en');
        return $lang->toNative() === 'en' ? $base : $this->load($domain, $lang->toNative()) + $base;
    }

    public function message(string $english, Language $lang): string
    {
        return $lang->toNative() === 'en' ? $english : ($this->load('messages', $lang->toNative())[$english] ?? $english);
    }

    /** Есть ли перевод интерфейса админки на язык. */
    public function hasAdmin(Language $lang): bool
    {
        return $lang->toNative() === 'en' || $this->load('admin', $lang->toNative()) !== [];
    }

    /** @return list<Language> языки, на которые переведена админка */
    public function adminLanguages(): array
    {
        $out = [Language::fromNative('en')];
        foreach (glob($this->dir . '/admin/*.json') ?: [] as $file) {
            $code = basename($file, '.json');
            if ($code !== 'en' && Language::tryParse($code, $l)) {
                $out[] = $l;
            }
        }
        return $out;
    }

    /** @return array<string, string> */
    private function load(string $domain, string $code): array
    {
        if (!in_array($domain, self::DOMAINS, true) || !preg_match('/^[a-z]{2}$/', $code)) {
            return [];
        }
        $key = $domain . '/' . $code;
        if (isset($this->loaded[$key])) {
            return $this->loaded[$key];
        }
        $file = $this->dir . '/' . $key . '.json';
        $raw = is_file($file) && filesize($file) <= self::MAX_BYTES ? file_get_contents($file) : false;
        $data = is_string($raw) ? json_decode($raw, true, 2) : null;
        $strings = [];
        foreach (is_array($data) ? $data : [] as $k => $v) {
            if (is_string($k) && is_string($v)) {
                $strings[$k] = $v;
            }
        }
        return $this->loaded[$key] = $strings;
    }
}
