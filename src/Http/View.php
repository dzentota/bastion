<?php
declare(strict_types=1);

namespace Bastion\Http;

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
        /** @var (\Closure(): list<array{title: string, url: string}>)|null */
        private readonly ?\Closure $siteMenu = null,
    ) {
    }

    /** @param array<string, mixed> $ctx */
    public function admin(ServerRequestInterface $request, string $template, array $ctx = [], int $status = 200): ResponseInterface
    {
        $token = $request->getAttribute(CsrfMiddleware::TOKEN_ATTRIBUTE);
        if (is_string($token)) {
            $ctx['csrf'] = $token;
        }
        return $this->html($this->admin->render(TemplateName::fromNative($template), $ctx), $status);
    }

    /** @param array<string, mixed> $ctx */
    public function theme(string $template, array $ctx, int $status = 200): ResponseInterface
    {
        if (is_array($ctx['site'] ?? null) && $this->siteMenu !== null) {
            $ctx['site']['menu'] = ($this->siteMenu)();
        }
        return $this->html($this->theme->render(TemplateName::fromNative($template), $ctx), $status);
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
