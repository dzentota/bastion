<?php
declare(strict_types=1);

namespace Bastion\Media\Application;

use Bastion\Media\Domain\{MediaKind, RejectedUpload};
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};

/**
 * Превращает недоверенные байты в безопасный файл (правило 2: наименее выразительный формат).
 *
 * Изображения: размеры проверяются по заголовку ДО декодирования, затем изображение
 * декодируется и кодируется заново через GD. Результат — только пиксели: EXIF/XMP/ICC,
 * комментарии и всё, что было «приклеено» к файлу (полиглоты), не переживают перекодирование.
 * PDF перекодировать нечем — он отклоняется при наличии активного содержимого
 * и всегда отдаётся как вложение в песочнице (MediaController).
 */
#[AssetId('bastion-app')]
#[AbuserStory('upload-rce')]
#[Mitigation(cwe: 'CWE-434', description: 'Type detected from content (magic bytes + finfo), allowlist without SVG/HTML; images re-encoded by GD; files stored under system keys in external storage or outside webroot')]
#[AbuserStory('exif-leak')]
#[Mitigation(cwe: 'CWE-212', description: 'Images re-encoded from pixels: EXIF/GPS, XMP and comments are dropped')]
#[AbuserStory('media-decompression-bomb')]
#[Mitigation(cwe: 'CWE-409', description: 'Width, height and total pixels checked from the header before decoding; byte size limit before reading')]
#[AbuserStory('media-content-sniffing')]
#[Mitigation(cwe: 'CWE-430', description: 'Client name and Content-Type ignored; sniffed type must agree with finfo; PDFs with JavaScript/actions/attachments/forms rejected')]
final class MediaSanitizer
{
    private const PDF_ACTIVE = ['/JavaScript', '/JS', '/Launch', '/EmbeddedFile', '/EmbeddedFiles', '/OpenAction', '/AA', '/RichMedia', '/XFA', '/AcroForm', '/SubmitForm', '/GoToR', '/Encrypt'];

    public function __construct(private readonly UploadPolicy $policy)
    {
    }

    public function sanitize(string $bytes): CleanFile
    {
        if (strlen($bytes) > $this->policy->maxBytes) {
            throw new RejectedUpload(RejectedUpload::TOO_LARGE);
        }
        $kind = MediaKind::sniff($bytes) ?? throw new RejectedUpload(RejectedUpload::UNSUPPORTED_TYPE);
        $finfoMime = (new \finfo(FILEINFO_MIME_TYPE))->buffer($bytes);
        if ($finfoMime !== $kind->mime()) {
            throw new RejectedUpload(RejectedUpload::TYPE_MISMATCH);
        }
        return $kind->isImage() ? $this->image($bytes, $kind) : $this->pdf($bytes);
    }

    private function image(string $bytes, MediaKind $kind): CleanFile
    {
        $info = @getimagesizefromstring($bytes);
        if ($info === false || $info[0] < 1 || $info[1] < 1) {
            throw new RejectedUpload(RejectedUpload::CORRUPT);
        }
        [$w, $h] = $info;
        if ($w > $this->policy->maxSide || $h > $this->policy->maxSide || $w * $h > $this->policy->maxPixels) {
            throw new RejectedUpload(RejectedUpload::TOO_MANY_PIXELS);
        }
        $img = @imagecreatefromstring($bytes);
        if ($img === false) {
            throw new RejectedUpload(RejectedUpload::CORRUPT);
        }
        if ($kind === MediaKind::Png || $kind === MediaKind::Webp) {
            imagesavealpha($img, true);
        }
        ob_start();
        $ok = match ($kind) {
            MediaKind::Jpeg => imagejpeg($img, null, 85),
            MediaKind::Png => imagepng($img, null, 9),
            MediaKind::Webp => imagewebp($img, null, 85),
            MediaKind::Gif => imagegif($img),
            MediaKind::Pdf => false,
        };
        $clean = (string) ob_get_clean();
        unset($img);
        if (!$ok || MediaKind::sniff($clean) !== $kind) {
            throw new RejectedUpload(RejectedUpload::CORRUPT);
        }
        return new CleanFile($kind, $clean, $w, $h);
    }

    private function pdf(string $bytes): CleanFile
    {
        // Имена в PDF можно записать через #XX-escape (/J#61vaScript) — нормализуем перед поиском.
        $normalized = (string) preg_replace_callback('/#([0-9A-Fa-f]{2})/', static fn (array $m) => chr(((int) hexdec($m[1])) & 0xFF), $bytes);
        foreach (self::PDF_ACTIVE as $name) {
            if (preg_match('~' . preg_quote($name, '~') . '(?![A-Za-z])~', $normalized)) {
                throw new RejectedUpload(RejectedUpload::ACTIVE_CONTENT);
            }
        }
        // Сжатые объектные потоки могут прятать словари от проверки выше.
        if (str_contains($normalized, '/ObjStm')) {
            throw new RejectedUpload(RejectedUpload::ACTIVE_CONTENT);
        }
        return new CleanFile(MediaKind::Pdf, $bytes, null, null);
    }
}
