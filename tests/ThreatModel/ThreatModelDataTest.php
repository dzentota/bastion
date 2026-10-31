<?php
declare(strict_types=1);

namespace Bastion\Tests\ThreatModel;

use Bastion\Release\ThreatModelExport;
use Bastion\ThreatModel\Domain\{InvalidThreatModel, ThreatModelData};
use PHPUnit\Framework\TestCase;

/** Abuser story: threat-model-export-tamper — экспорт разбирается строго. */
final class ThreatModelDataTest extends TestCase
{
    /** @var array<string, mixed> */
    private static array $export;

    public static function setUpBeforeClass(): void
    {
        self::$export = ThreatModelExport::build(dirname(__DIR__, 2));
    }

    public function testRealExportIsDeterministicAndParses(): void
    {
        self::assertSame(json_encode(self::$export), json_encode(ThreatModelExport::build(dirname(__DIR__, 2))));
        $m = ThreatModelData::fromJson((string) json_encode(self::$export));
        self::assertNotNull($s = $m->story('revision-tamper'));
        self::assertSame('covered', $s['status']);
        self::assertNotSame([], $s['mitigations']);
        self::assertSame('tests/Attack/Http/RevisionsHttpTest.php', $s['tests'][0]['file']);
        self::assertNotSame([], $m->flows);
    }

    /** @return iterable<string, array{callable(array<string, mixed>): array<string, mixed>}> */
    public static function tampered(): iterable
    {
        yield 'other format' => [static fn (array $d) => ['format' => 'x'] + $d];
        yield 'future version' => [static fn (array $d) => ['version' => 2] + $d];
        yield 'unknown status' => [static function (array $d) { $d['stories'][0]['status'] = 'trust-me'; return $d; }];
        yield 'path traversal' => [static function (array $d) { $d['stories'][0]['mitigations'][0]['file'] = '../../etc/passwd'; return $d; }];
        yield 'absolute path' => [static function (array $d) { $d['stories'][0]['tests'][0]['file'] = '/etc/passwd'; return $d; }];
        yield 'bidi in text' => [static function (array $d) { $d['stories'][0]['title'] = "ok\u{202E}evil"; return $d; }];
        yield 'flow to unknown component' => [static function (array $d) { $d['flows'][0]['to'] = 'nowhere'; return $d; }];
        yield 'bad id' => [static function (array $d) { $d['components'][0]['id'] = '<script>'; return $d; }];
        yield 'bad cwe' => [static function (array $d) { $d['stories'][0]['requiredCwes'][0] = 'javascript:alert(1)'; return $d; }];
        yield 'severity' => [static function (array $d) { $d['findings'][0]['severity'] = 'none'; return $d; }];
        yield 'not a list' => [static function (array $d) { $d['stories'] = ['a' => $d['stories'][0]]; return $d; }];
    }

    /** @dataProvider tampered */
    #[\PHPUnit\Framework\Attributes\DataProvider('tampered')]
    public function testTamperedExportIsRejectedAsAWhole(callable $tamper): void
    {
        $this->expectException(InvalidThreatModel::class);
        ThreatModelData::fromJson((string) json_encode($tamper(self::$export)));
    }

    public function testOversizedAndMalformedInputIsRejected(): void
    {
        foreach ([str_repeat(' ', ThreatModelData::MAX_BYTES + 1), '{', '[]', 'null'] as $bad) {
            try {
                ThreatModelData::fromJson($bad);
                self::fail('accepted');
            } catch (InvalidThreatModel) {
                self::addToAssertionCount(1);
            }
        }
    }
}
