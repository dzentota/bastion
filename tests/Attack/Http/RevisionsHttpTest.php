<?php
declare(strict_types=1);

namespace Bastion\Tests\Attack\Http;

use Bastion\IdentityAccess\Domain\{NewPassword, Role, Username};
use Bastion\IdentityAccess\Infrastructure\AccountRepository;
use Bastion\Infrastructure\Database\Connection;
use Bastion\Tests\Support\HttpHarness;
use ParagonIE\Halite\KeyFactory;
use PHPUnit\Framework\TestCase;
use SecureDb\Db;

/** Ревизии. Abuser stories: unpublished-change-leak, revision-tamper, revision-snooping. */
final class RevisionsHttpTest extends TestCase
{
    private HttpHarness $h;
    private Db $db;

    protected function setUp(): void
    {
        $this->h = new HttpHarness();
        $this->h->installAndLogin();
        $this->db = Connection::sqlite($this->h->paths->sqlite());
    }

    public function testSavedChangesGoLiveOnlyWhenPublished(): void
    {
        $id = $this->create('page', 'First');
        $this->publish($id);
        $this->save($id, 'Second');

        $anon = $this->h->fresh();
        self::assertStringContainsString('First', (string) $anon->get('/en/page')->getBody(), 'на сайте прежняя версия');
        self::assertStringNotContainsString('Second', (string) $anon->get('/en/page')->getBody());
        $this->h->get("/admin/entries/{$id}/edit");
        self::assertStringContainsString('value="Second"', $this->h->body(), 'редактор показывает последнюю ревизию');
        self::assertStringContainsString('Publish changes', $this->h->body());

        $this->publish($id);
        self::assertStringContainsString('Second', (string) $anon->get('/en/page')->getBody());
        $this->h->get("/admin/entries/{$id}/edit");
        self::assertStringNotContainsString('Publish changes', $this->h->body());
    }

    public function testHistoryAndRollback(): void
    {
        $id = $this->create('page', 'One');
        $this->save($id, 'Two');
        $this->save($id, 'Two'); // без изменений — ревизии нет
        $this->save($id, 'Three');
        self::assertSame(3, $this->revisionCount($id));

        $this->h->get("/admin/entries/{$id}/revisions");
        self::assertStringContainsString('Revision history verified', $this->h->body());
        self::assertSame(303, $this->h->post("/admin/entries/{$id}/revisions/1/restore", [])->getStatusCode());
        self::assertSame(4, $this->revisionCount($id));
        self::assertSame('One', $this->db->selectCell('SELECT title FROM ?_entries WHERE id = ?', $id), 'черновик: рабочая копия откатилась');
        $this->h->get("/admin/entries/{$id}/revisions");
        self::assertStringContainsString('restored from #1', $this->h->body());

        $this->h->get('/admin/audit');
        self::assertStringContainsString('revision_restored', $this->h->body());
        foreach (['/revisions/0/restore', '/revisions/99/restore', '/revisions/01/restore', '/revisions/x/restore'] as $path) {
            $this->h->get("/admin/entries/{$id}/revisions");
            self::assertContains($this->h->post("/admin/entries/{$id}{$path}", [])->getStatusCode(), [404], $path);
        }
    }

    public function testTamperedHistoryBlocksPublishingAndRollback(): void
    {
        $id = $this->create('page', 'Honest');
        $this->publish($id);
        $this->save($id, 'Edited');
        $this->db->query("UPDATE ?_entry_revisions SET title = 'Injected' WHERE entry_id = ? AND seq = 2", $id);

        $this->h->get("/admin/entries/{$id}/revisions");
        self::assertStringContainsString('failed its integrity check', $this->h->body());
        self::assertStringNotContainsString('>Restore<', $this->h->body());
        $this->h->get("/admin/entries/{$id}/edit");
        self::assertSame(409, $this->h->post("/admin/entries/{$id}/publish", [])->getStatusCode());
        $this->h->get("/admin/entries/{$id}/edit");
        self::assertSame(404, $this->h->post("/admin/entries/{$id}/revisions/1/restore", [])->getStatusCode());
        self::assertStringNotContainsString('Injected', (string) $this->h->fresh()->get('/en/page')->getBody());
    }

    public function testDeletedOrForgedRevisionsBreakTheChain(): void
    {
        $id = $this->create('page', 'A');
        $this->save($id, 'B');
        $this->save($id, 'C');
        $this->db->query('DELETE FROM ?_entry_revisions WHERE entry_id = ? AND seq = 2', $id);
        $this->h->get("/admin/entries/{$id}/revisions");
        self::assertStringContainsString('failed its integrity check', $this->h->body(), 'удаление из середины');

        $other = $this->create('other', 'X');
        $row = $this->db->selectRow('SELECT * FROM ?_entry_revisions WHERE entry_id = ?', $other);
        $this->db->insert('?_entry_revisions', ['id' => '00000000-0000-4000-8000-000000000001', 'seq' => 2, 'title' => 'Forged', 'mac' => str_repeat('a', 64)] + $row);
        $this->h->get("/admin/entries/{$other}/revisions");
        self::assertStringContainsString('failed its integrity check', $this->h->body(), 'вставка');
    }

    public function testEntriesFromBeforeRevisionsGetABaseline(): void
    {
        $id = $this->create('legacy', 'Legacy');
        $this->publish($id);
        $this->db->query('DELETE FROM ?_entry_revisions');
        $this->db->query('UPDATE ?_entries SET published_revision = NULL');
        $this->save($id, 'Newer');
        self::assertSame(2, $this->revisionCount($id));
        self::assertStringContainsString('Legacy', (string) $this->h->fresh()->get('/en/legacy')->getBody());
        $this->h->get("/admin/entries/{$id}/revisions");
        self::assertStringContainsString('Live', $this->h->body());
    }

    public function testAuthorCannotReadOrRestoreOthersHistory(): void
    {
        $id = $this->create('owners', 'Owner');
        $this->save($id, 'Owner 2');
        $u = Username::fromNative('writer');
        (new AccountRepository($this->db, KeyFactory::loadEncryptionKey($this->h->paths->encryptionKey())))
            ->create($u, NewPassword::forUser('another long passphrase here', $u), Role::Author);
        $author = $this->h->fresh();
        $author->get('/admin/login');
        $author->post('/admin/login', ['username' => 'writer', 'password' => 'another long passphrase here']);
        self::assertSame(404, $author->get("/admin/entries/{$id}/revisions")->getStatusCode());
        $author->get('/admin');
        self::assertSame(404, $author->post("/admin/entries/{$id}/revisions/1/restore", [])->getStatusCode());
        self::assertSame(2, $this->revisionCount($id));
    }

    private function create(string $slug, string $title): string
    {
        $this->h->get('/admin/entries/new?type=page');
        $res = $this->h->post('/admin/entries', ['type' => 'page', 'title' => $title, 'slug' => $slug, 'blocks' => [['type' => 'paragraph', 'text' => 'Body']]]);
        preg_match('~/admin/entries/([0-9a-f-]+)/edit~', $res->getHeaderLine('Location'), $m);
        return $m[1];
    }

    private function save(string $id, string $title): void
    {
        $this->h->get("/admin/entries/{$id}/edit");
        preg_match('~name="slug" value="([^"]+)"~', $this->h->body(), $s);
        self::assertSame(303, $this->h->post("/admin/entries/{$id}", ['title' => $title, 'slug' => $s[1], 'blocks' => [['type' => 'paragraph', 'text' => 'Body']]])->getStatusCode());
    }

    private function publish(string $id): void
    {
        $this->h->get("/admin/entries/{$id}/edit");
        self::assertSame(303, $this->h->post("/admin/entries/{$id}/publish", [])->getStatusCode());
    }

    private function revisionCount(string $id): int
    {
        return (int) $this->db->selectCell('SELECT COUNT(*) FROM ?_entry_revisions WHERE entry_id = ?', $id);
    }
}
