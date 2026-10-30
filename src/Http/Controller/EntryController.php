<?php
declare(strict_types=1);

namespace Bastion\Http\Controller;

use Bastion\Content\Domain\{Entry, EntryId, EntryType, Slug, Title};
use Bastion\Content\Domain\Block\{Block, BlockList, Heading, InvalidBlock, Paragraph, Quote};
use Bastion\Content\Infrastructure\EntryRepository;
use Bastion\Http\Middleware\RequireStaff;
use Bastion\Http\View;
use Bastion\IdentityAccess\Domain\{Account, Capability};
use Bastion\SecurityMonitoring\Domain\{ActorKey, AppSensor, DetectionPoint};
use Psr\Http\Message\{ResponseInterface, ServerRequestInterface};
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};

/** Abuser stories: privilege-escalation, stored-xss-block, csrf-publish, sqli-content. */
#[AssetId('bastion-app')]
final class EntryController
{
    private const EDITOR_ROWS = 12;

    public function __construct(
        private readonly EntryRepository $entries,
        private readonly View $view,
        private readonly AppSensor $sensor,
        private readonly \Psr\Clock\ClockInterface $clock,
    ) {
    }

    public function index(ServerRequestInterface $request): ResponseInterface
    {
        $account = $this->account($request);
        $rows = array_map(fn (Entry $e) => [
            'id' => $e->id->toNative(), 'title' => $e->title(), 'status' => $e->status()->value,
            'url' => '/' . $e->slug()->toNative(), 'published' => $e->isPublished(),
        ], $this->entries->latest(100, false));
        return $this->view->admin($request, 'dashboard', ['entries' => $rows, 'me' => ['name' => $account->username]]);
    }

    public function create(ServerRequestInterface $request): ResponseInterface
    {
        return $this->editor($request, null, ['title' => '', 'slug' => ''], [], []);
    }

    public function edit(ServerRequestInterface $request, EntryId $id): ResponseInterface
    {
        $entry = $this->entries->find($id);
        if ($entry === null || !$this->mayEdit($request, $entry)) {
            return $this->view->admin($request, 'not-found', [], 404);
        }
        $rows = [];
        foreach ($entry->blocks() as $b) {
            $rows[] = ['type' => $b::type()] + array_map('strval', $b->toArray());
        }
        return $this->editor($request, $entry, ['title' => $entry->title(), 'slug' => $entry->slug()], $rows, []);
    }

    public function store(ServerRequestInterface $request): ResponseInterface
    {
        return $this->save($request, null);
    }

    public function update(ServerRequestInterface $request, EntryId $id): ResponseInterface
    {
        $entry = $this->entries->find($id);
        if ($entry === null || !$this->mayEdit($request, $entry)) {
            return $this->view->admin($request, 'not-found', [], 404);
        }
        return $this->save($request, $entry);
    }

    public function publish(ServerRequestInterface $request, EntryId $id): ResponseInterface
    {
        $entry = $this->entries->find($id);
        if ($entry === null || !$this->mayEdit($request, $entry)) {
            return $this->view->admin($request, 'not-found', [], 404);
        }
        if (!$this->account($request)->role->can(Capability::ContentPublish)) {
            return $this->forbidden($request);
        }
        $entry->publish($this->clock->now());
        $this->entries->save($entry);
        return $this->view->redirect('/admin');
    }

    private function save(ServerRequestInterface $request, ?Entry $entry): ResponseInterface
    {
        $errors = [];
        $rawTitle = Input::string($request, 'title', 1000);
        $rawSlug = Input::string($request, 'slug', 200);
        $rows = Input::rows($request, 'blocks', BlockList::MAX_BLOCKS);
        Title::tryParse($rawTitle, $title) || $errors[] = 'Title: 1–200 characters, single line.';
        Slug::tryParse($rawSlug, $slug) || $errors[] = 'Slug: lowercase letters, digits and dashes.';
        if ($slug && $this->entries->slugTaken($slug, $entry?->id)) {
            $errors[] = 'This slug is already used.';
        }
        try {
            $blocks = $this->blocksFromRows($rows);
        } catch (InvalidBlock) {
            $blocks = null;
            $errors[] = 'One of the blocks is invalid.';
        }
        $this->detectXss($request, $rawTitle, $rawSlug, ...array_column($rows, 'text'));
        if ($errors !== []) {
            $this->sensor->event(DetectionPoint::IE2, ActorKey::ip($this->ip($request)));
            return $this->editor($request, $entry, ['title' => $rawTitle, 'slug' => $rawSlug], $rows, $errors, 422);
        }

        if ($entry === null) {
            $entry = Entry::draft(EntryType::Post, $title, $slug, $blocks, $this->account($request)->getId());
        } else {
            $entry->revise($title, $slug, $blocks);
        }
        $this->entries->save($entry);
        return $this->view->redirect('/admin/entries/' . $entry->id->toNative() . '/edit');
    }

    /** @param list<array<string, string>> $rows */
    private function blocksFromRows(array $rows): BlockList
    {
        $blocks = [];
        foreach ($rows as $row) {
            $text = $row['text'] ?? '';
            if (trim($text) === '') {
                continue; // пустые строки редактора игнорируются
            }
            $text = str_replace("\r\n", "\n", $text);
            $blocks[] = match ($row['type'] ?? '') {
                'paragraph' => Paragraph::fromArray(['text' => $text]),
                'quote' => Quote::fromArray(['text' => $text]),
                'heading' => Heading::fromArray(['text' => $text, 'level' => 2]),
                default => throw new InvalidBlock('type'),
            };
        }
        return BlockList::of(...$blocks);
    }

    /**
     * @param array<string, mixed> $values
     * @param list<array<string, string>> $rows
     * @param list<string> $errors
     */
    private function editor(ServerRequestInterface $request, ?Entry $entry, array $values, array $rows, array $errors, int $status = 200): ResponseInterface
    {
        while (count($rows) < self::EDITOR_ROWS) {
            $rows[] = ['type' => 'paragraph', 'text' => ''];
        }
        $rows = array_map(static fn (array $r, int $i) => [
            'i' => $i, 'text' => $r['text'] ?? '',
            'is_paragraph' => ($r['type'] ?? '') === 'paragraph', 'is_heading' => ($r['type'] ?? '') === 'heading',
            'is_quote' => ($r['type'] ?? '') === 'quote',
        ], $rows, array_keys($rows));
        $account = $this->account($request);
        return $this->view->admin($request, 'editor', [
            'entry' => $entry ? ['id' => $entry->id->toNative(), 'published' => $entry->isPublished()] : null,
            'action' => $entry ? '/admin/entries/' . $entry->id->toNative() : '/admin/entries',
            'values' => $values,
            'rows' => $rows,
            'errors' => $errors,
            'can_publish' => $account->role->can(Capability::ContentPublish),
        ], $status);
    }

    #[AbuserStory('privilege-escalation')]
    #[Mitigation(cwe: 'CWE-285', description: 'Capability checks per action (edit_others, publish); violations raise AppSensor ACE3')]
    private function mayEdit(ServerRequestInterface $request, Entry $entry): bool
    {
        $account = $this->account($request);
        if ($entry->authorId === $account->getId() || $account->role->can(Capability::ContentEditOthers)) {
            return true;
        }
        $this->sensor->event(DetectionPoint::ACE3, ActorKey::account($account->getId()));
        return false;
    }

    private function forbidden(ServerRequestInterface $request): ResponseInterface
    {
        $this->sensor->event(DetectionPoint::ACE3, ActorKey::account($this->account($request)->getId()));
        return $this->view->admin($request, 'forbidden', [], 403);
    }

    /** IE1: признаки XSS-пейлоада во вводе. Это сигнал, а не защита — защита в типах и экранировании. */
    private function detectXss(ServerRequestInterface $request, string ...$values): void
    {
        foreach ($values as $v) {
            if (preg_match('/<\s*script|javascript:|on\w+\s*=|<\s*iframe|<\s*svg/i', $v)) {
                $this->sensor->event(DetectionPoint::IE1, ActorKey::ip($this->ip($request)));
                return;
            }
        }
    }

    private function account(ServerRequestInterface $request): Account
    {
        $a = $request->getAttribute(RequireStaff::ACCOUNT);
        return $a instanceof Account ? $a : throw new \LogicException('RequireStaff middleware missing');
    }

    private function ip(ServerRequestInterface $request): string
    {
        return (string) ($request->getServerParams()['REMOTE_ADDR'] ?? 'unknown');
    }
}
