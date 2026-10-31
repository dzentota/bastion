<?php
declare(strict_types=1);

namespace Bastion\Taxonomy\Domain;

use Bastion\Content\Domain\Slug;

/** Элемент таксономии; идентифицируется видом и слагом (слаг же служит подписью). */
final class Term
{
    public function __construct(public readonly TermKind $kind, public readonly Slug $slug)
    {
    }

    public function url(): string
    {
        return '/' . $this->kind->value . '/' . $this->slug->toNative();
    }
}
