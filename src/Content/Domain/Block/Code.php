<?php
declare(strict_types=1);

namespace Bastion\Content\Domain\Block;

use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};

/**
 * Фрагмент кода. Язык — подпись из закрытого списка (класс language-*), подсветки нет:
 * скрипты на клиенте запрещены CSP, а текст выводится как есть, только экранированным.
 */
#[AssetId('bastion-app')]
#[AbuserStory('trojan-source')]
#[Mitigation(cwe: 'CWE-1007', description: 'Block text rejects bidirectional override/isolate characters (Trojan Source) and other control characters except tab and newlines')]
final class Code implements Block
{
    public const LANGUAGES = ['text', 'php', 'bash', 'json', 'yaml', 'sql', 'html', 'css', 'js', 'ini', 'diff', 'nginx', 'apache'];

    public function __construct(public readonly string $language, public readonly BlockText $text)
    {
        if (!in_array($language, self::LANGUAGES, true)) {
            throw new InvalidBlock('code.language');
        }
    }

    public static function type(): string
    {
        return 'code';
    }

    public function toArray(): array
    {
        return ['language' => $this->language, 'text' => $this->text->toNative()];
    }

    public static function fromArray(array $data): static
    {
        BlockText::tryParse($data['text'] ?? null, $text) || throw new InvalidBlock('code.text');
        $language = $data['language'] ?? 'text';
        is_string($language) || throw new InvalidBlock('code.language');
        return new static($language, $text);
    }
}
