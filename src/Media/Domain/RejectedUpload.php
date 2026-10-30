<?php
declare(strict_types=1);

namespace Bastion\Media\Domain;

final class RejectedUpload extends \DomainException
{
    public const TOO_LARGE = 'too_large';
    public const UNSUPPORTED_TYPE = 'unsupported_type';
    public const TYPE_MISMATCH = 'type_mismatch';
    public const TOO_MANY_PIXELS = 'too_many_pixels';
    public const CORRUPT = 'corrupt';
    public const ACTIVE_CONTENT = 'active_content';
    public const QUOTA = 'quota';
    public const UPLOAD_ERROR = 'upload_error';

    public function __construct(public readonly string $reason)
    {
        parent::__construct($reason);
    }

    public function userMessage(): string
    {
        return match ($this->reason) {
            self::TOO_LARGE => 'The file is too large.',
            self::UNSUPPORTED_TYPE, self::TYPE_MISMATCH => 'Only JPEG, PNG, WebP, GIF and PDF files are allowed.',
            self::TOO_MANY_PIXELS => 'The image dimensions are too large.',
            self::CORRUPT => 'The file is damaged or cannot be processed.',
            self::ACTIVE_CONTENT => 'PDF files with scripts, attachments or forms are not allowed.',
            self::QUOTA => 'Upload limit reached. Try again later.',
            default => 'The upload failed.',
        };
    }
}
