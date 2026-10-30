<?php
declare(strict_types=1);

namespace Bastion\Media\Domain;

/**
 * Разрешённые типы (ADR-0011). SVG, HTML и всё прочее запрещены.
 * Тип определяется только по содержимому — имя и Content-Type клиента игнорируются.
 */
enum MediaKind: string
{
    case Jpeg = 'jpeg';
    case Png = 'png';
    case Webp = 'webp';
    case Gif = 'gif';
    case Pdf = 'pdf';

    public static function sniff(string $bytes): ?self
    {
        return match (true) {
            str_starts_with($bytes, "\xFF\xD8\xFF") => self::Jpeg,
            str_starts_with($bytes, "\x89PNG\r\n\x1A\n") => self::Png,
            str_starts_with($bytes, 'RIFF') && substr($bytes, 8, 4) === 'WEBP' => self::Webp,
            str_starts_with($bytes, 'GIF87a'), str_starts_with($bytes, 'GIF89a') => self::Gif,
            str_starts_with($bytes, '%PDF-') => self::Pdf,
            default => null,
        };
    }

    public function mime(): string
    {
        return match ($this) {
            self::Jpeg => 'image/jpeg',
            self::Png => 'image/png',
            self::Webp => 'image/webp',
            self::Gif => 'image/gif',
            self::Pdf => 'application/pdf',
        };
    }

    public function extension(): string
    {
        return $this === self::Jpeg ? 'jpg' : $this->value;
    }

    public function isImage(): bool
    {
        return $this !== self::Pdf;
    }
}
