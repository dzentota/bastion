<?php
declare(strict_types=1);

namespace Bastion\Tests\Attack\Http;

use Bastion\Http\Kernel;
use Bastion\Infrastructure\Database\Connection;
use Bastion\Tests\Support\HttpHarness;
use PHPUnit\Framework\TestCase;

/** ADR из репозитория в CMS (ADR-0025). Abuser story: managed-content-override. */
final class AdrSyncTest extends TestCase
{
    private HttpHarness $h;
    private string $adr;

    protected function setUp(): void
    {
        $this->h = new HttpHarness();
        $this->h->installAndLogin(languages: 'ru, en');
        $this->adr = $this->h->paths->root . '/docs/adr';
        mkdir($this->adr . '/en', 0777, true);
        file_put_contents($this->adr . '/0001-first.md', "# ADR-0001: Первое решение\n\n- Статус: принято\n\n## Контекст\n\nТекст с `кодом` и [ссылкой](https://example.org).\n\n```bash\nbin/bastion migrate\n```\n");
        file_put_contents($this->adr . '/0002-second.md', "# ADR-0002: Второе\n\nАбзац.\n");
        file_put_contents($this->adr . '/en/0001-first.md', "# ADR-0001: First decision\n\nEnglish text.\n");
        file_put_contents($this->adr . '/notes.md', "# Not an ADR\n");
        symlink('/etc/hosts', $this->adr . '/0003-link.md');
    }

    private function sync(): string
    {
        return implode("\n", (new Kernel($this->h->paths, false, true))->syncAdrs('ru'));
    }

    public function testSyncPublishesReadOnlyPagesAndTracksChanges(): void
    {
        $report = $this->sync();
        self::assertStringContainsString('created docs/adr/0001-first.md', $report);
        self::assertStringContainsString('created docs/adr/en/0001-first.md', $report);
        self::assertStringNotContainsString('notes.md', $report);
        self::assertStringNotContainsString('0003', $report, 'символическая ссылка не читается');

        $anon = $this->h->fresh();
        $page = (string) $anon->get('/ru/adr-0001')->getBody();
        self::assertStringContainsString('ADR-0001: Первое решение', $page);
        self::assertStringContainsString('Текст с кодом и ссылкой (https://example.org).', $page);
        self::assertStringContainsString('<code class="language-bash">bin/bastion migrate</code>', $page);
        self::assertStringContainsString('<a href="/ru/adr">Архитектурные решения</a>', $page, 'под страницей-оглавлением');
        self::assertStringContainsString('hreflang="en" href="/en/adr-0001"', $page, 'перевод связан');
        self::assertStringContainsString('ADR-0002', (string) $anon->get('/ru/adr')->getBody());

        self::assertStringNotContainsString('updated', $this->sync(), 'без изменений — без новых ревизий');
        file_put_contents($this->adr . '/0002-second.md', "# ADR-0002: Второе\n\nИзменённый абзац.\n");
        self::assertStringContainsString('updated docs/adr/0002-second.md', $this->sync());
        self::assertStringContainsString('Изменённый абзац.', (string) $anon->get('/ru/adr-0002')->getBody());
        $db = Connection::sqlite($this->h->paths->sqlite());
        $id = (string) $db->selectCell("SELECT id FROM ?_entries WHERE source = 'docs/adr/0002-second.md'");
        self::assertSame(2, (int) $db->selectCell('SELECT COUNT(*) FROM ?_entry_revisions WHERE entry_id = ?', $id));
    }

    public function testManagedPagesCannotBeChangedInTheCms(): void
    {
        $this->sync();
        $db = Connection::sqlite($this->h->paths->sqlite());
        $id = (string) $db->selectCell("SELECT id FROM ?_entries WHERE source = 'docs/adr/0001-first.md'");
        $this->h->get("/admin/entries/{$id}/edit");
        self::assertStringContainsString('<code>docs/adr/0001-first.md</code>', $this->h->body());
        self::assertSame(403, $this->h->post("/admin/entries/{$id}", ['title' => 'Hijacked', 'slug' => 'adr-0001', 'blocks' => [['type' => 'paragraph', 'text' => 'x']]])->getStatusCode());
        $this->h->get("/admin/entries/{$id}/edit");
        self::assertSame(403, $this->h->post("/admin/entries/{$id}/publish", [])->getStatusCode());
        $this->h->get("/admin/entries/{$id}/edit");
        self::assertSame(403, $this->h->post("/admin/entries/{$id}/revisions/1/restore", [])->getStatusCode());
        $this->h->get("/admin/entries/{$id}/edit");
        self::assertSame(403, $this->h->post("/admin/entries/{$id}/translations", ['lang' => 'en'])->getStatusCode());
        self::assertSame('ADR-0001: Первое решение', $db->selectCell('SELECT title FROM ?_entries WHERE id = ?', $id));
    }

    public function testAPageEditedInTheCmsIsNeverOverwritten(): void
    {
        $this->h->get('/admin/entries/new?type=page');
        $this->h->post('/admin/entries', ['type' => 'page', 'lang' => 'ru', 'title' => 'Моя страница', 'slug' => 'adr-0002', 'blocks' => [['type' => 'paragraph', 'text' => 'моё']]]);
        self::assertStringContainsString('error   docs/adr/0002-second.md: /ru/adr-0002 is used by a page edited in the CMS', $this->sync());
        self::assertSame('Моя страница', Connection::sqlite($this->h->paths->sqlite())->selectCell("SELECT title FROM ?_entries WHERE slug = 'adr-0002'"));
    }
}
