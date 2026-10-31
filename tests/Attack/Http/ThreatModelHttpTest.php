<?php
declare(strict_types=1);

namespace Bastion\Tests\Attack\Http;

use Bastion\Release\ThreatModelExport;
use Bastion\Tests\Support\HttpHarness;
use PHPUnit\Framework\TestCase;

/** Сайт документации: модель угроз. Abuser stories: threat-model-export-tamper, svg-injection. */
final class ThreatModelHttpTest extends TestCase
{
    private HttpHarness $h;

    protected function setUp(): void
    {
        $this->h = new HttpHarness();
        $this->h->installAndLogin(languages: 'en, ru');
    }

    private function export(?callable $tamper = null): void
    {
        @mkdir($this->h->paths->root . '/build');
        $d = ThreatModelExport::build(dirname(__DIR__, 3));
        file_put_contents($this->h->paths->threatModel(), json_encode($tamper !== null ? $tamper($d) : $d));
    }

    public function testEmbeddedViewsAndStoryPages(): void
    {
        $this->export();
        $this->h->get('/admin/entries/new?type=page');
        $res = $this->h->post('/admin/entries', ['type' => 'page', 'title' => 'Security', 'slug' => 'security', 'blocks' => [
            ['type' => 'paragraph', 'text' => 'Hand-written intro.'],
            ['type' => 'threatmodel', 'option' => 'overview', 'text' => ''],
            ['type' => 'threatmodel', 'option' => 'dfd', 'text' => ''],
            ['type' => 'threatmodel', 'option' => 'matrix', 'text' => ''],
        ]]);
        self::assertSame(303, $res->getStatusCode(), $this->h->body());
        $edit = $res->getHeaderLine('Location');
        $this->h->get($edit);
        self::assertStringContainsString('<option value="dfd" selected>', $this->h->body());
        $this->h->post(str_replace('/edit', '/publish', $edit), []);

        $anon = $this->h->fresh();
        $page = (string) $anon->get('/en/security')->getBody();
        self::assertStringContainsString('Hand-written intro.', $page);
        self::assertStringContainsString('<svg class="dfd"', $page);
        self::assertStringContainsString('href="/en/threats/revision-tamper"', $page);
        $stories = count(ThreatModelExport::build(dirname(__DIR__, 3))['stories']);
        self::assertStringContainsString("{$stories} covered", $page);

        $story = (string) $anon->get('/en/threats/revision-tamper')->getBody();
        self::assertStringContainsString('src/Content/Infrastructure/RevisionRepository.php', $story);
        self::assertStringContainsString('tests/Attack/Http/RevisionsHttpTest.php', $story);
        self::assertStringContainsString('<title>Rewrite content history in the database — Bastion</title>', $story);
        self::assertStringContainsString('Тесты атак', (string) $anon->get('/ru/threats/revision-tamper')->getBody());
        self::assertSame(200, $anon->get('/en/threats')->getStatusCode());
        foreach (['/en/threats/no-such-story', '/xx/threats', '/xx/threats/revision-tamper', '/en/threats/..%2F..%2Fetc'] as $url) {
            self::assertSame(404, $anon->get($url)->getStatusCode(), $url);
        }
    }

    public function testMissingOrTamperedExportDegradesQuietly(): void
    {
        $this->h->get('/admin/entries/new?type=page');
        $res = $this->h->post('/admin/entries', ['type' => 'page', 'title' => 'S', 'slug' => 's', 'blocks' => [['type' => 'threatmodel', 'option' => 'overview', 'text' => '']]]);
        $this->h->get($res->getHeaderLine('Location'));
        $this->h->post(str_replace('/edit', '/publish', $res->getHeaderLine('Location')), []);

        self::assertStringContainsString('not available', (string) $this->h->fresh()->get('/en/s')->getBody());
        $this->export(static function (array $d): array {
            $d['stories'][0]['status'] = 'covered-trust-me';
            return $d;
        });
        $res = $this->h->fresh()->get('/en/s');
        self::assertSame(200, $res->getStatusCode());
        self::assertStringContainsString('not available', (string) $res->getBody());
        self::assertSame(404, $this->h->fresh()->get('/en/threats/hijack-installer')->getStatusCode());
    }
}
