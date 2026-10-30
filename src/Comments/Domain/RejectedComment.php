<?php
declare(strict_types=1);

namespace Bastion\Comments\Domain;

final class RejectedComment extends \DomainException
{
    public const INVALID = 'invalid';
    public const CLOSED = 'closed';
    public const RATE_LIMIT = 'rate_limit';
    public const QUEUE_FULL = 'queue_full';
    public const RESERVED_NAME = 'reserved_name';

    public function __construct(public readonly string $reason)
    {
        parent::__construct($reason);
    }

    public function userMessage(): string
    {
        return match ($this->reason) {
            self::RATE_LIMIT, self::QUEUE_FULL => 'Too many comments right now. Please try again later.',
            self::RESERVED_NAME => 'Please choose a different name.',
            self::CLOSED => 'Comments are not available for this page.',
            default => 'Please write a name (up to 60 characters) and a comment (up to 5000 characters).',
        };
    }
}
