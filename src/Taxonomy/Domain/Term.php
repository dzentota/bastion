<?php
declare(strict_types=1);

namespace Bastion\Taxonomy\Domain;

use Bastion\Content\Domain\{Language, Slug};

/** Элемент таксономии; идентифицируется видом и слагом (слаг же служит подписью). */
final class Term
{
    public function __construct(public readonly TermKind $kind, public readonly Slug $slug)
    {
    }

    /** Листинг термина на языке: термины общие для всех языков, записи — нет. */
    public function url(Language $lang): string
    {
        return '/' . $lang->toNative() . '/' . $this->kind->value . '/' . $this->slug->toNative();
    }
}
