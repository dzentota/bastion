<?php
declare(strict_types=1);

namespace Bastion\Http;

use Bastion\Content\Domain\{Entry, Language, SiteLanguages};
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};

/** Общие данные публичных шаблонов: язык страницы, переключатель языков, hreflang. */
#[AssetId('bastion-app')]
final class SiteContext
{
    public function __construct(public readonly SiteLanguages $languages)
    {
    }

    /**
     * @param list<Entry> $translations опубликованные варианты текущей записи (для переключателя и hreflang)
     * @return array<string, mixed>
     */
    #[AbuserStory('draft-translation-leak')]
    #[Mitigation(cwe: 'CWE-200', description: 'Language switcher and hreflang links list only published variants; a missing translation links to that language home page')]
    public function for(Language $lang, array $translations = []): array
    {
        $byLang = [];
        foreach ($translations as $t) {
            if ($t->isPublished()) {
                $byLang[$t->lang->toNative()] = $t->path();
            }
        }
        $switch = [];
        foreach ($this->languages->all as $l) {
            $code = $l->toNative();
            // без перевода переключатель ведёт на главную этого языка
            $switch[] = ['lang' => $code, 'url' => $byLang[$code] ?? '/' . $code, 'current' => $code === $lang->toNative()];
        }
        return [
            'name' => 'Bastion',
            'lang' => $lang->toNative(),
            'home' => '/' . $lang->toNative(),
            'languages' => count($switch) > 1 ? $switch : [],
            'alternates' => count($byLang) > 1 ? array_map(static fn (string $c, string $u) => ['lang' => $c, 'url' => $u], array_keys($byLang), $byLang) : [],
        ];
    }

    /** @return array<string, mixed> для страниц вне языка (404 по неизвестному адресу) */
    public function default(): array
    {
        return $this->for($this->languages->default);
    }
}
