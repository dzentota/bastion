<?php
declare(strict_types=1);

namespace Bastion\Tests\Support;

/** Генерация тестовых файлов без бинарных фикстур в репозитории. */
final class MediaFixtures
{
    public static function image(string $format = 'jpeg', int $w = 32, int $h = 24): string
    {
        $img = imagecreatetruecolor($w, $h);
        imagefill($img, 0, 0, (int) imagecolorallocate($img, 200, 30, 30));
        ob_start();
        match ($format) {
            'jpeg' => imagejpeg($img),
            'png' => imagepng($img),
            'webp' => imagewebp($img),
            'gif' => imagegif($img),
        };
        return (string) ob_get_clean();
    }

    /** JPEG с APP1/EXIF-сегментом, содержащим маркер GPS и полезную нагрузку. */
    public static function jpegWithExif(string $payload): string
    {
        $jpeg = self::image('jpeg');
        $exif = "Exif\0\0" . 'MM' . "\0\x2A\0\0\0\x08" . 'GPSLatitude=54.6872;GPSLongitude=25.2797;' . $payload;
        $app1 = "\xFF\xE1" . pack('n', strlen($exif) + 2) . $exif;
        return substr($jpeg, 0, 2) . $app1 . substr($jpeg, 2);
    }

    /** PNG, который заявляет гигантские размеры (заголовок валиден, данных нет). */
    public static function pngBomb(int $w = 50_000, int $h = 50_000): string
    {
        $ihdr = pack('NNCCCCC', $w, $h, 8, 2, 0, 0, 0);
        $chunk = static fn (string $type, string $data) => pack('N', strlen($data)) . $type . $data . pack('N', crc32($type . $data));
        return "\x89PNG\r\n\x1A\n" . $chunk('IHDR', $ihdr) . $chunk('IDAT', (string) gzcompress(str_repeat("\0", 1024))) . $chunk('IEND', '');
    }

    public static function pdf(string $extra = ''): string
    {
        return "%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R {$extra} >> endobj\n"
            . "2 0 obj << /Type /Pages /Kids [] /Count 0 >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n";
    }
}
