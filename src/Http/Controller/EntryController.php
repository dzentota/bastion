<?php
declare(strict_types=1);

namespace Bastion\Http\Controller;

use Bastion\Audit\Domain\{AuditAction, AuditTrail};
use Bastion\Content\Domain\{Entry, EntryId, EntryType, Language, MenuPosition, Revision, RevisionNumber, SiteLanguages, Slug, Title};
use Bastion\Content\Infrastructure\RevisionRepository;
use Bastion\IdentityAccess\Infrastructure\AccountRepository;
use Bastion\Content\Domain\Block\{Block, BlockList, Heading, Image, InvalidBlock, Paragraph, Quote};
use Bastion\Media\Domain\{MediaId, MediaItem};
use Bastion\Media\Infrastructure\MediaRepository;
use Bastion\Content\Infrastructure\EntryRepository;
use Bastion\Http\Middleware\RequireStaff;
use Bastion\Http\View;
use Bastion\IdentityAccess\Domain\{Account, Capability};
use Bastion\SecurityMonitoring\Domain\{ActorKey, AppSensor, DetectionPoint};
use Bastion\Taxonomy\Domain\{TermKind, TermList};
use Bastion\Taxonomy\Infrastructure\TermRepository;
use Psr\Http\Message\{ResponseInterface, ServerRequestInterface};
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};

/** Abuser stories: privilege-escalation, stored-xss-block, csrf-publish, sqli-content. */
#[AssetId('bastion-app')]
final class EntryController
{
    private const EDITOR_ROWS = 12;
    /** Первые сегменты путей, занятые маршрутами: запись с таким слагом была бы недостижима или маскировалась под систему. */
    private const RESERVED_SLUGS = ['admin', 'category', 'tag', 'media', 'comments', 'install', 'assets', 'login', 'feed'];

    public function __construct(
        private readonly EntryRepository $entries,
        private readonly View $view,
        private readonly AppSensor $sensor,
        private readonly \Psr\Clock\ClockInterface $clock,
        private readonly MediaRepository $media,
        private readonly AuditTrail $audit,
        private readonly TermRepository $terms,
        private readonly \Bastion\SecurityMonitoring\Application\SecurityPosture $posture,
        private readonly \Bastion\Content\Infrastructure\MenuRepository $menu,
        private readonly SiteLanguages $languages,
        private readonly RevisionRepository $revisions,
        private readonly AccountRepository $accounts,
    ) {
    }

    public function index(ServerRequestInterface $request): ResponseInterface
    {
        $account = $this->account($request);
        $rows = array_map(fn (Entry $e) => [
            'id' => $e->id->toNative(), 'title' => $e->title(), 'status' => $e->status()->value, 'type' => $e->type->value,
            'url' => $e->path(), 'lang' => $e->lang->toNative(), 'published' => $e->isPublished(), 'is_page' => $e->type === EntryType::Page,
        ], $this->entries->latest(100, false));
        return $this->view->admin($request, 'dashboard', [
            'entries' => $rows, 'me' => ['name' => $account->username],
            // детали конфигурации — только тем, кто может её менять
            'notices' => $account->role->can(Capability::SecurityView) ? $this->posture->notices() : [],
        ]);
    }

    public function create(ServerRequestInterface $request): ResponseInterface
    {
        $type = ($request->getQueryParams()['type'] ?? null) === 'page' ? EntryType::Page : EntryType::Post;
        return $this->editor($request, null, ['title' => '', 'slug' => '', 'categories' => '', 'tags' => '', 'type' => $type->value, 'lang' => $this->languages->default->toNative(), 'in_menu' => false, 'menu_position' => '10'], [], []);
    }

    public function edit(ServerRequestInterface $request, EntryId $id): ResponseInterface
    {
        $entry = $this->entries->find($id);
        if ($entry === null || !$this->mayEdit($request, $entry)) {
            return $this->view->admin($request, 'not-found', [], 404);
        }
        $this->revisions->ensureBaseline($entry);
        $head = $this->revisions->head($entry->id);
        $rows = [];
        foreach ($head->blocks ?? $entry->blocks() as $b) {
            $data = array_map('strval', $b->toArray());
            $rows[] = $b instanceof Image
                ? ['type' => 'image', 'media' => $data['media'], 'text' => $data['alt']]
                : ['type' => $b::type()] + $data;
        }
        return $this->editor($request, $entry, [
            'title' => $head->title ?? $entry->title(), 'slug' => $head->slug ?? $entry->slug(), 'type' => $entry->type->value, 'lang' => $entry->lang->toNative(),
            'categories' => $this->terms->forEntry($entry->id, TermKind::Category)->toInput(),
            'tags' => $this->terms->forEntry($entry->id, TermKind::Tag)->toInput(),
            'in_menu' => ($pos = $this->menu->positionOf($entry->id)) !== null,
            'menu_position' => $pos?->toNative() ?? '10',
        ], $rows, []);
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
        $this->revisions->ensureBaseline($entry);
        $chain = $this->revisions->chain($entry->id);
        $head = $chain->revisions[0] ?? null;
        if (!$chain->intact || $head === null) {
            return $this->view->admin($request, 'integrity', ['error' => 'Revision history failed its integrity check; publishing is blocked.'], 409);
        }
        if ($this->entries->slugTaken($entry->lang, $head->slug, $entry->id)) {
            return $this->view->redirect('/admin/entries/' . $entry->id->toNative() . '/edit?error=slug');
        }
        $entry->revise($head->title, $head->slug, $head->blocks);
        $entry->publish($this->clock->now());
        $this->entries->save($entry);
        $this->revisions->markPublished($entry->id, $head->id);
        $this->audit->record(AuditAction::EntryPublished, $this->account($request)->getId(), $entry->id->toNative(), $this->ip($request));
        return $this->view->redirect('/admin');
    }

    #[AbuserStory('revision-snooping')]
    #[Mitigation(cwe: 'CWE-285', description: 'History and rollback use the same edit-rights check as the editor (own entries, or content.edit_others)')]
    public function history(ServerRequestInterface $request, EntryId $id): ResponseInterface
    {
        $entry = $this->entries->find($id);
        if ($entry === null || !$this->mayEdit($request, $entry)) {
            return $this->view->admin($request, 'not-found', [], 404);
        }
        $this->revisions->ensureBaseline($entry);
        $chain = $this->revisions->chain($entry->id);
        $published = $this->revisions->publishedId($entry->id);
        $head = $chain->revisions[0] ?? null;
        return $this->view->admin($request, 'revisions', [
            'entry' => ['id' => $entry->id->toNative(), 'title' => $entry->title()],
            'intact' => $chain->intact,
            'broken_at' => (string) ($chain->brokenAt ?? ''),
            'revisions' => array_map(fn (Revision $r) => [
                'seq' => (string) $r->seq, 'at' => $r->createdAt->format('Y-m-d H:i'), 'title' => $r->title,
                'author' => $this->authorName($r->authorId),
                'published' => $r->id->toNative() === $published, 'head' => $r === $head,
                'restored_from' => $r->restoredFrom !== null ? (string) $r->restoredFrom : null,
                'has_previous' => $r->seq > 1,
            ], $chain->revisions),
        ]);
    }

    #[AbuserStory('revision-tamper')]
    #[Mitigation(cwe: 'CWE-345', description: 'Rollback is refused when the revision chain fails verification, so injected rows cannot be promoted to the working copy')]
    public function restore(ServerRequestInterface $request, EntryId $id, RevisionNumber $seq): ResponseInterface
    {
        $entry = $this->entries->find($id);
        if ($entry === null || !$this->mayEdit($request, $entry)) {
            return $this->view->admin($request, 'not-found', [], 404);
        }
        $chain = $this->revisions->chain($entry->id);
        $old = $this->revisions->find($entry->id, $seq->toInt());
        if ($old === null || !$chain->intact) {
            return $this->view->admin($request, 'not-found', [], 404);
        }
        if (!$entry->isPublished()) {
            $entry->revise($old->title, $old->slug, $old->blocks);
            $this->entries->save($entry);
        }
        $this->revisions->record($entry, $old->title, $old->slug, $old->blocks, $this->account($request)->getId(), $old->seq);
        $this->audit->record(AuditAction::RevisionRestored, $this->account($request)->getId(), $entry->id->toNative(), $this->ip($request));
        return $this->view->redirect('/admin/entries/' . $entry->id->toNative() . '/edit');
    }

    /** @var array<string, string> */
    private array $authorNames = [];

    private function authorName(string $id): string
    {
        return $this->authorNames[$id] ??= $this->accounts->find($id)?->username->toNative() ?? $id;
    }

    /** Черновик перевода в той же группе: блоки и заголовок исходника — отправная точка. */
    #[AbuserStory('translation-hijack')]
    #[Mitigation(cwe: 'CWE-285', description: 'Adding a translation requires edit rights on the source entry; the language must be a configured site language not yet present in the group')]
    public function translate(ServerRequestInterface $request, EntryId $id): ResponseInterface
    {
        $source = $this->entries->find($id);
        if ($source === null || !$this->mayEdit($request, $source)) {
            return $this->view->admin($request, 'not-found', [], 404);
        }
        $lang = $this->languages->resolve(Input::string($request, 'lang', 8));
        $taken = array_map(static fn (Entry $e) => $e->lang->toNative(), $this->entries->translations($source->translationGroup));
        if ($lang === null || in_array($lang->toNative(), $taken, true)) {
            $this->sensor->event(DetectionPoint::IE2, ActorKey::ip($this->ip($request)));
            return $this->view->redirect('/admin/entries/' . $source->id->toNative() . '/edit');
        }
        $slug = $source->slug();
        if ($this->entries->slugTaken($lang, $slug)) {
            $slug = Slug::tryParse(substr($slug->toNative(), 0, 92) . '-' . $lang->toNative(), $s) ? $s : $slug;
        }
        $copy = $source->translate($lang, $source->title(), $slug, $this->account($request)->getId());
        $this->entries->save($copy);
        $this->revisions->record($copy, $copy->title(), $copy->slug(), $copy->blocks(), $this->account($request)->getId());
        $this->audit->record(AuditAction::EntryCreated, $this->account($request)->getId(), $copy->id->toNative(), $this->ip($request));
        return $this->view->redirect('/admin/entries/' . $copy->id->toNative() . '/edit');
    }

    #[AbuserStory('unpublished-change-leak')]
    #[Mitigation(cwe: 'CWE-200', description: 'Saving a published entry only appends a revision; the public row changes when a publisher publishes that revision')]
    private function save(ServerRequestInterface $request, ?Entry $entry): ResponseInterface
    {
        $errors = [];
        $rawTitle = Input::string($request, 'title', 1000);
        $rawSlug = Input::string($request, 'slug', 200);
        $rows = Input::rows($request, 'blocks', BlockList::MAX_BLOCKS);
        // тип задаётся при создании и дальше не меняется
        $type = $entry->type ?? EntryType::tryFrom(Input::string($request, 'type', 8) ?: EntryType::Post->value);
        $type ?? $errors[] = 'Unknown entry type.';
        // язык, как и тип, фиксируется при создании; перевод — отдельная запись
        // без поля — язык по умолчанию; присланное значение (в т.ч. пустое или слишком длинное) обязано быть языком сайта
        $body = $request->getParsedBody();
        $sentLang = is_array($body) && array_key_exists('lang', $body);
        $lang = $entry->lang ?? ($sentLang ? $this->languages->resolve(Input::string($request, 'lang', 8)) : $this->languages->default);
        $lang ?? $errors[] = 'Unknown language.';
        $inFeed = $type?->inFeed() ?? true;
        $rawCategories = $inFeed ? Input::string($request, 'categories', 600) : '';
        $rawTags = $inFeed ? Input::string($request, 'tags', 1600) : '';
        $inMenu = !$inFeed && Input::string($request, 'in_menu', 1) === '1';
        $rawPosition = $inFeed ? '' : Input::string($request, 'menu_position', 16);
        $rawPosition = $rawPosition === '' ? '10' : $rawPosition; // '0' в PHP ложно — без ?:
        $position = null;
        if ($inMenu && !MenuPosition::tryParse($rawPosition, $position)) {
            $errors[] = 'Menu position: a number from 1 to 99.';
        }
        $categories = TermList::parse(TermKind::Category, $rawCategories);
        $tags = TermList::parse(TermKind::Tag, $rawTags);
        $categories ?? $errors[] = 'Categories: up to 5 comma-separated slugs.';
        $tags ?? $errors[] = 'Tags: up to 15 comma-separated slugs.';
        Title::tryParse($rawTitle, $title) || $errors[] = 'Title: 1–200 characters, single line.';
        Slug::tryParse($rawSlug, $slug) || $errors[] = 'Slug: lowercase letters, digits and dashes.';
        if ($slug && in_array($slug->toNative(), self::RESERVED_SLUGS, true)) {
            $errors[] = 'This slug is reserved by the system.';
        }
        if ($slug && $lang && $this->entries->slugTaken($lang, $slug, $entry?->id)) {
            $errors[] = 'This slug is already used.';
        }
        try {
            $blocks = $this->blocksFromRows($rows);
        } catch (InvalidBlock) {
            $blocks = null;
            $errors[] = 'One of the blocks is invalid.';
        }
        $this->detectXss($request, $rawTitle, $rawSlug, ...array_column($rows, 'text'));
        $menuValues = ['in_menu' => $inMenu, 'menu_position' => $rawPosition];
        if ($errors !== [] || $categories === null || $tags === null || $type === null || $lang === null || $title === null || $slug === null || $blocks === null) {
            $this->sensor->event(DetectionPoint::IE2, ActorKey::ip($this->ip($request)));
            return $this->editor($request, $entry, ['title' => $rawTitle, 'slug' => $rawSlug, 'categories' => $rawCategories, 'tags' => $rawTags, 'type' => $type->value ?? 'post', 'lang' => $lang?->toNative() ?? $this->languages->default->toNative()] + $menuValues, $rows, $errors, 422);
        }

        $action = $entry === null ? AuditAction::EntryCreated : AuditAction::EntryUpdated;
        if ($entry === null) {
            $entry = Entry::draft($type, $lang, $title, $slug, $blocks, $this->account($request)->getId());
            $this->entries->save($entry);
        } else {
            $this->revisions->ensureBaseline($entry);
            if (!$entry->isPublished()) {
                // черновик: строка entries — рабочая копия; у опубликованной — то, что на сайте, до «Опубликовать»
                $entry->revise($title, $slug, $blocks);
                $this->entries->save($entry);
            }
        }
        $this->revisions->record($entry, $title, $slug, $blocks, $this->account($request)->getId());
        if (!$this->terms->assign($entry->id, $categories) || !$this->terms->assign($entry->id, $tags)) {
            return $this->editor($request, $entry, ['title' => $rawTitle, 'slug' => $rawSlug, 'categories' => $rawCategories, 'tags' => $rawTags, 'type' => $type->value, 'lang' => $lang->toNative()],
                $rows, ['The site has reached the limit of distinct categories or tags; reuse existing ones.'], 422);
        }
        $this->menu->place($entry->id, $inMenu ? $position : null);
        $this->audit->record($action, $this->account($request)->getId(), $entry->id->toNative(), $this->ip($request));
        return $this->view->redirect('/admin/entries/' . $entry->id->toNative() . '/edit');
    }

    /** @param list<array<string, string>> $rows */
    private function blocksFromRows(array $rows): BlockList
    {
        $blocks = [];
        foreach ($rows as $row) {
            $text = str_replace("\r\n", "\n", $row['text'] ?? '');
            if (($row['type'] ?? '') === 'image') {
                if (($row['media'] ?? '') === '') {
                    continue;
                }
                $image = Image::fromArray(['media' => $row['media'], 'alt' => trim($text)]);
                $this->media->find($image->media) ?? throw new InvalidBlock('image.media not found');
                $blocks[] = $image;
                continue;
            }
            if (trim($text) === '') {
                continue; // пустые строки редактора игнорируются
            }
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
        $library = array_filter($this->media->latest(100), static fn (MediaItem $m) => $m->kind->isImage());
        $rows = array_map(static fn (array $r, int $i) => [
            'i' => $i, 'text' => $r['text'] ?? '',
            'is_paragraph' => ($r['type'] ?? '') === 'paragraph', 'is_heading' => ($r['type'] ?? '') === 'heading',
            'is_quote' => ($r['type'] ?? '') === 'quote', 'is_image' => ($r['type'] ?? '') === 'image',
            'media' => array_values(array_map(static fn (MediaItem $m) => [
                'id' => $m->id->toNative(), 'name' => $m->name, 'selected' => ($r['media'] ?? '') === $m->id->toNative(),
            ], $library)),
        ], $rows, array_keys($rows));
        $account = $this->account($request);
        $current = is_string($values['lang'] ?? null) ? $values['lang'] : $this->languages->default->toNative();
        return $this->view->admin($request, 'editor', [
            'entry' => $entry ? [
                'id' => $entry->id->toNative(), 'published' => $entry->isPublished(), 'lang' => $entry->lang->toNative(),
                // у опубликованной записи есть сохранённые, но не опубликованные изменения
                'pending' => $entry->isPublished() && ($h = $this->revisions->head($entry->id)) !== null && $h->id->toNative() !== $this->revisions->publishedId($entry->id),
            ] : null,
            'slug_conflict' => ($request->getQueryParams()['error'] ?? null) === 'slug',
            // язык выбирается только у новой записи
            'languages' => $entry === null && count($this->languages->all) > 1
                ? array_map(static fn (Language $l) => ['code' => $l->toNative(), 'selected' => $l->toNative() === $current], $this->languages->all)
                : [],
            'translations' => $entry === null || count($this->languages->all) < 2 ? [] : $this->translationRows($entry),
            'action' => $entry ? '/admin/entries/' . $entry->id->toNative() : '/admin/entries',
            'values' => $values,
            'is_page' => ($values['type'] ?? 'post') === 'page',
            'rows' => $rows,
            'errors' => $errors,
            'can_publish' => $account->role->can(Capability::ContentPublish),
        ], $status);
    }

    /** @return list<array<string, mixed>> по строке на язык сайта: вариант есть — ссылка, нет — кнопка «добавить» */
    private function translationRows(Entry $entry): array
    {
        $variants = [];
        foreach ($this->entries->translations($entry->translationGroup) as $v) {
            $variants[$v->lang->toNative()] = $v;
        }
        $rows = [];
        foreach ($this->languages->all as $l) {
            $v = $variants[$l->toNative()] ?? null;
            $rows[] = [
                'lang' => $l->toNative(), 'current' => $v !== null && $v->id->isSame($entry->id),
                'edit' => $v !== null ? '/admin/entries/' . $v->id->toNative() . '/edit' : null,
                'status' => $v?->status()->value, 'published' => $v?->isPublished() ?? false, 'title' => $v?->title(),
            ];
        }
        return $rows;
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
