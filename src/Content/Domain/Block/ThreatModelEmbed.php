<?php
declare(strict_types=1);

namespace Bastion\Content\Domain\Block;

use Bastion\ThreatModel\Rendering\ThreatModelViews;

/** Встроенное представление модели угроз (ADR-0023): блок хранит только выбор вида, данные — из экспорта релиза. */
final class ThreatModelEmbed implements Block
{
    public function __construct(public readonly string $view)
    {
        if (!in_array($view, ThreatModelViews::VIEWS, true)) {
            throw new InvalidBlock('threatmodel.view');
        }
    }

    public static function type(): string
    {
        return 'threatmodel';
    }

    public function toArray(): array
    {
        return ['view' => $this->view];
    }

    public static function fromArray(array $data): static
    {
        $view = $data['view'] ?? null;
        is_string($view) || throw new InvalidBlock('threatmodel.view');
        return new static($view);
    }
}
