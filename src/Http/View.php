<?php
declare(strict_types=1);

namespace Bastion\Http;

use Bastion\Content\Domain\Language;
use Bastion\Http\Middleware\RequireStaff;
use Bastion\IdentityAccess\Domain\Account;
use Bastion\Shared\I18n\StringCatalog;
use Bastion\Theming\Dsl\{Renderer, TemplateName};
use dzentota\Router\Middleware\CsrfMiddleware;
use Psr\Http\Message\{ResponseFactoryInterface, ResponseInterface, ServerRequestInterface};

/** Рендер HTML-страниц через Template DSL + CSRF-токен для форм. */
final class View
{
    public function __construct(
        private readonly Renderer $admin,
        private readonly Renderer $theme,
        private readonly ResponseFactoryInterface $responses,
        /** @var (\Closure(Language): list<array{title: string, url: string}>)|null */
        private readonly ?\Closure $siteMenu = null,
        private readonly ?StringCatalog $catalog = null,
        private readonly ?Language $defaultLanguage = null,
    ) {
    }

    /** Язык админки: выбор пользователя → язык сайта по умолчанию → английский (если нет перевода). */
    public function adminLanguage(ServerRequestInterface $request): Language
    {
        $account = $request->getAttribute(RequireStaff::ACCOUNT);
        foreach ([$account instanceof Account ? $account->locale : null, $this->defaultLanguage] as $candidate) {
            if ($candidate !== null && $this->catalog?->hasAdmin($candidate)) {
                return $candidate;
            }
        }
        return Language::fromNative('en');
    }

    /** @param array<string, mixed> $ctx */
    public function admin(ServerRequestInterface $request, string $template, array $ctx = [], int $status = 200): ResponseInterface
    {
        $token = $request->getAttribute(CsrfMiddleware::TOKEN_ATTRIBUTE);
        if (is_string($token)) {
            $ctx['csrf'] = $token;
        }
        $lang = $this->adminLanguage($request);
        $ctx['ui_lang'] = $lang->toNative();
        if ($this->catalog !== null) {
            $ctx['t'] = $this->catalog->strings('admin', $lang);
            // сообщения контроллеров — английский текст как ключ
            if (is_array($ctx['errors'] ?? null)) {
                $ctx['errors'] = array_map(fn (mixed $e) => is_string($e) ? $this->catalog->message($e, $lang) : $e, $ctx['errors']);
            }
            if (is_string($ctx['error'] ?? null)) {
                $ctx['error'] = $this->catalog->message($ctx['error'], $lang);
            }
            $account = $request->getAttribute(RequireStaff::ACCOUNT);
            if ($account instanceof Account) {
                // оболочка админки: кто вошёл и какой раздел навигации текущий
                $sections = ['content' => ['dashboard', 'editor', 'revisions', 'revision-diff'], 'media' => ['media'], 'comments' => ['comments'],
                    'menu' => ['menu'], 'audit' => ['audit'], 'extensions' => ['extensions'], 'database' => ['database']];
                $ctx['staff'] = ['name' => $account->username->toNative(), 'nav' => array_map(static fn (array $t) => in_array($template, $t, true), $sections)];
            }
            $languages = $this->catalog->adminLanguages();
            $ctx['ui_languages'] = $account instanceof Account && count($languages) > 1
                ? array_map(static fn (Language $l) => ['code' => $l->toNative(), 'current' => $l->toNative() === $lang->toNative()], $languages)
                : [];
        }
        return $this->html($this->admin->render(TemplateName::fromNative($template), $ctx), $status);
    }

    /** @param array<string, mixed> $ctx */
    public function theme(string $template, array $ctx, int $status = 200): ResponseInterface
    {
        $lang = is_array($ctx['site'] ?? null) && Language::tryParse($ctx['site']['lang'] ?? null, $l) ? $l : null;
        if ($lang !== null && $this->siteMenu !== null) {
            $ctx['site']['menu'] = ($this->siteMenu)($lang);
        }
        if ($this->catalog !== null) {
            $lang ??= $this->defaultLanguage ?? Language::fromNative('en');
            $ctx['t'] = $this->catalog->strings('theme', $lang);
            if (is_array($ctx['comment_form'] ?? null) && is_string($ctx['comment_form']['error'] ?? null)) {
                $ctx['comment_form']['error'] = $this->catalog->message($ctx['comment_form']['error'], $lang);
            }
        }
        return $this->html($this->theme->render(TemplateName::fromNative($template), $ctx), $status);
    }

    /** 301 для переехавших адресов (старые /{slug} до i18n). Те же ограничения, что у redirect(). */
    #[\HybridTM\Attributes\AbuserStory('legacy-redirect-abuse')]
    #[\HybridTM\Attributes\Mitigation(cwe: 'CWE-601', description: 'Legacy-URL redirects are built from stored entries and pass the local-path allowlist of View::redirect')]
    public function moved(string $path): ResponseInterface
    {
        return $this->redirect($path)->withStatus(301);
    }

    public function redirect(string $path): ResponseInterface
    {
        // только локальные пути (плюс простая query-строка key=value) — нет open redirect
        if (!preg_match('~^/(?!/)[A-Za-z0-9/_-]*(\?[a-z_]+=[a-z0-9_-]+)?$~', $path)) {
            $path = '/';
        }
        return $this->responses->createResponse(303)->withHeader('Location', $path);
    }

    private function html(string $html, int $status): ResponseInterface
    {
        $r = $this->responses->createResponse($status)->withHeader('Content-Type', 'text/html; charset=utf-8');
        $r->getBody()->write($html);
        return $r;
    }
}
