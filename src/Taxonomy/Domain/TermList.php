<?php
declare(strict_types=1);

namespace Bastion\Taxonomy\Domain;

use Bastion\Content\Domain\Slug;

/** Набор терминов одного вида для записи: без дублей, не больше лимита вида. */
final class TermList
{
    /** @param list<Term> $terms */
    private function __construct(public readonly TermKind $kind, public readonly array $terms)
    {
    }

    public static function of(TermKind $kind, Slug ...$slugs): self
    {
        $terms = [];
        foreach ($slugs as $slug) {
            $terms[$slug->toNative()] = new Term($kind, $slug);
        }
        return new self($kind, array_values(array_slice($terms, 0, $kind->perEntryLimit())));
    }

    /** Разбор ввода редактора «php, security». Null — ввод невалиден. */
    public static function parse(TermKind $kind, string $input): ?self
    {
        $terms = [];
        foreach (explode(',', $input) as $part) {
            $part = trim($part);
            if ($part === '') {
                continue;
            }
            if (!Slug::tryParse($part, $slug)) {
                return null;
            }
            $terms[$slug->toNative()] = new Term($kind, $slug);
        }
        return count($terms) <= $kind->perEntryLimit() ? new self($kind, array_values($terms)) : null;
    }

    public function toInput(): string
    {
        return implode(', ', array_map(static fn (Term $t) => $t->slug->toNative(), $this->terms));
    }
}
