<?php
declare(strict_types=1);

namespace Bastion\Http;

use Bastion\Theming\Dsl\{Renderer, TemplateName};
use Dzentota\Session\Middleware\SessionMiddleware;
use Dzentota\Session\SessionManager;
use Psr\Http\Message\{ResponseFactoryInterface, ResponseInterface, ServerRequestInterface};

/** Рендер HTML-страниц через Template DSL + CSRF-токен для форм. */
final class View
{
    public function __construct(
        private readonly Renderer $admin,
        private readonly Renderer $theme,
        private readonly ResponseFactoryInterface $responses,
    ) {
    }

    /** @param array<string, mixed> $ctx */
    public function admin(ServerRequestInterface $request, string $template, array $ctx = [], int $status = 200): ResponseInterface
    {
        $session = $request->getAttribute(SessionMiddleware::SESSION_ATTRIBUTE);
        if ($session instanceof SessionManager) {
            $ctx['csrf'] = $session->generateCsrfToken()->toNative();
        }
        return $this->html($this->admin->render(TemplateName::fromNative($template), $ctx), $status);
    }

    /** @param array<string, mixed> $ctx */
    public function theme(string $template, array $ctx, int $status = 200): ResponseInterface
    {
        return $this->html($this->theme->render(TemplateName::fromNative($template), $ctx), $status);
    }

    public function redirect(string $path): ResponseInterface
    {
        // только локальные пути — нет open redirect
        if (!preg_match('~^/(?!/)[A-Za-z0-9/_-]*$~', $path)) {
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
