<?php
declare(strict_types=1);

namespace Bastion\Tests\ThreatModel;

use Bastion\Release\ThreatModelExport;
use Bastion\ThreatModel\Domain\ThreatModelData;
use Bastion\ThreatModel\Rendering\{DfdSvg, ThreatModelViews};
use PHPUnit\Framework\TestCase;

/** Abuser story: svg-injection — разметку SVG задаёт только код. */
final class DfdSvgTest extends TestCase
{
    public function testHostileNamesStayText(): void
    {
        $d = ThreatModelExport::build(dirname(__DIR__, 2));
        $d['components'][5]['name'] = '</text><script>alert(1)</script><text onload="x" (a "b" & c)';
        $d['flows'][0]['description'] = ']]><svg onload=alert(1)>';
        $d['stories'][0]['title'] = '<img src=x onerror=alert(1)>';
        $m = ThreatModelData::fromJson((string) json_encode($d));

        $svg = DfdSvg::render($m, 'Diagram "x" <y>')['svg'];
        $doc = simplexml_load_string($svg);
        self::assertNotFalse($doc, 'well-formed SVG');
        self::assertStringNotContainsString('<script', $svg);
        self::assertDoesNotMatchRegularExpression('/\son\w+\s*=/', strip_tags(str_replace('&quot;', '', $svg)) === '' ? '' : preg_replace('/>[^<]*</', '><', $svg) ?? '');
        self::assertCount(0, $doc->xpath('//*[local-name()="script" or local-name()="foreignObject"]') ?: []);

        $html = (new ThreatModelViews([], 'en'))->render('matrix', $m) . (new ThreatModelViews([], 'en'))->render('dfd', $m);
        self::assertStringNotContainsString('<img', $html);
        self::assertStringContainsString('&lt;img src=x onerror=alert(1)&gt;', $html);
    }

    public function testEveryFlowIsDrawnAndNumbered(): void
    {
        $m = ThreatModelData::fromJson((string) json_encode(ThreatModelExport::build(dirname(__DIR__, 2))));
        $r = DfdSvg::render($m, 'D');
        self::assertCount(count($m->flows), $r['numbers']);
        self::assertSame(count($m->flows), substr_count($r['svg'], 'class="dfd-flow"'));
    }
}
