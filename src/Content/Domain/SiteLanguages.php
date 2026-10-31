<?php
declare(strict_types=1);

namespace Bastion\Content\Domain;

use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};

/**
 * Языки сайта из config.json (site.languages, site.default_language).
 * Сайт без этих ключей — одноязычный английский.
 */
#[AssetId('bastion-app')]
final class SiteLanguages
{
    public const MAX = 10;

    /** @param non-empty-list<Language> $all */
    private function __construct(public readonly array $all, public readonly Language $default)
    {
    }

    /** @param mixed $languages @param mixed $default */
    public static function fromConfig(mixed $languages, mixed $default): self
    {
        $all = [];
        foreach (is_array($languages) ? array_slice($languages, 0, self::MAX) : [] as $code) {
            if (Language::tryParse($code, $lang) && !in_array($lang->toNative(), array_map(static fn (Language $l) => $l->toNative(), $all), true)) {
                $all[] = $lang;
            }
        }
        $fallback = $all[0] ?? Language::fromNative('en');
        $def = Language::tryParse($default, $d) ? $d : $fallback;
        if ($all === [] || !in_array($def->toNative(), array_map(static fn (Language $l) => $l->toNative(), $all), true)) {
            array_unshift($all, $def);
        }
        return new self($all, $def);
    }

    /** Код из URL или формы, если это язык сайта. */
    #[AbuserStory('language-parameter-abuse')]
    #[Mitigation(cwe: 'CWE-20', description: 'Language codes from URLs and forms are accepted only from the configured allowlist; anything else is a 404 or a validation error')]
    public function resolve(mixed $code): ?Language
    {
        foreach ($this->all as $lang) {
            if (is_string($code) && $lang->toNative() === $code) {
                return $lang;
            }
        }
        return null;
    }

    /** @return list<string> */
    public function codes(): array
    {
        return array_map(static fn (Language $l) => $l->toNative(), $this->all);
    }
}
