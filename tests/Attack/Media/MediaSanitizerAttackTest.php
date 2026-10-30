<?php
declare(strict_types=1);

namespace Bastion\Tests\Attack\Media;

use Bastion\Media\Application\{MediaSanitizer, UploadPolicy};
use Bastion\Media\Domain\{MediaKind, RejectedUpload};
use Bastion\Tests\Support\MediaFixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** Abuser stories: upload-rce, exif-leak, media-decompression-bomb, media-content-sniffing. */
final class MediaSanitizerAttackTest extends TestCase
{
    private function sanitizer(int $maxBytes = 10 * 1024 * 1024): MediaSanitizer
    {
        return new MediaSanitizer(new UploadPolicy(maxBytes: $maxBytes));
    }

    private function rejects(string $bytes, string $reason, ?MediaSanitizer $s = null): void
    {
        try {
            ($s ?? $this->sanitizer())->sanitize($bytes);
            self::fail('Upload was accepted');
        } catch (RejectedUpload $e) {
            self::assertSame($reason, $e->reason);
        }
    }

    public static function formats(): iterable
    {
        foreach (['jpeg', 'png', 'webp', 'gif'] as $f) {
            yield $f => [$f];
        }
    }

    #[DataProvider('formats')]
    public function testCleanImagesAreAcceptedAndReencoded(string $format): void
    {
        $clean = $this->sanitizer()->sanitize(MediaFixtures::image($format));
        self::assertSame(MediaKind::from($format), $clean->kind);
        self::assertSame([32, 24], [$clean->width, $clean->height]);
    }

    public function testPhpScriptIsRejectedWhateverItIsCalled(): void
    {
        $this->rejects('<?php system($_GET["c"]); ?>', RejectedUpload::UNSUPPORTED_TYPE);
    }

    public function testGifPhpPolyglotIsRejected(): void
    {
        // Классика: "GIF89a" + PHP. Байты PHP попадают в поля размеров заголовка — изображение отклоняется.
        $this->expectException(RejectedUpload::class);
        $this->sanitizer()->sanitize("GIF89a<?php system(\$_GET['c']); ?>");
    }

    public function testPayloadAppendedToRealImageDoesNotSurvive(): void
    {
        $polyglot = MediaFixtures::image('png') . '<?php system($_GET["c"]); ?>';
        $clean = $this->sanitizer()->sanitize($polyglot);
        self::assertStringNotContainsString('<?php', $clean->bytes);
    }

    public function testExifAndGpsAreStripped(): void
    {
        $clean = $this->sanitizer()->sanitize(MediaFixtures::jpegWithExif('<?php echo 1; ?>'));
        self::assertStringNotContainsString('Exif', $clean->bytes);
        self::assertStringNotContainsString('GPSLatitude', $clean->bytes);
        self::assertStringNotContainsString('<?php', $clean->bytes);
    }

    public function testDecompressionBombIsRejectedBeforeDecoding(): void
    {
        $before = memory_get_usage();
        $this->rejects(MediaFixtures::pngBomb(), RejectedUpload::TOO_MANY_PIXELS);
        self::assertLessThan(5 * 1024 * 1024, memory_get_usage() - $before);
        $this->rejects(MediaFixtures::pngBomb(20_000, 10), RejectedUpload::TOO_MANY_PIXELS);
    }

    public static function scriptableFormats(): iterable
    {
        yield 'svg' => ['<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>'];
        yield 'svg with xml prolog' => ['<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'];
        yield 'html' => ['<!doctype html><script>alert(document.cookie)</script>'];
        yield 'html disguised' => ["\xEF\xBB\xBF<html><body onload=alert(1)>"];
        yield 'empty' => [''];
    }

    #[DataProvider('scriptableFormats')]
    public function testScriptableFormatsAreRejected(string $bytes): void
    {
        $this->rejects($bytes, RejectedUpload::UNSUPPORTED_TYPE);
    }

    public static function activePdfs(): iterable
    {
        yield 'javascript' => ['/OpenAction << /S /JavaScript /JS (app.alert(1)) >>'];
        yield 'escaped name' => ['/Names << /J#61vaScript 3 0 R >>'];
        yield 'launch' => ['/AA << /O << /S /Launch /F (cmd.exe) >> >>'];
        yield 'embedded file' => ['/Names << /EmbeddedFiles 4 0 R >>'];
        yield 'form' => ['/AcroForm << /XFA 5 0 R >>'];
        yield 'object stream' => ['/Type /ObjStm'];
    }

    #[DataProvider('activePdfs')]
    public function testPdfWithActiveContentIsRejected(string $extra): void
    {
        $this->rejects(MediaFixtures::pdf($extra), RejectedUpload::ACTIVE_CONTENT);
    }

    public function testPlainPdfIsAccepted(): void
    {
        self::assertSame(MediaKind::Pdf, $this->sanitizer()->sanitize(MediaFixtures::pdf())->kind);
    }

    public function testSizeLimitIsEnforcedBeforeParsing(): void
    {
        $this->rejects(MediaFixtures::image('png'), RejectedUpload::TOO_LARGE, $this->sanitizer(maxBytes: 10));
    }
}
