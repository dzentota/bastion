<?php
declare(strict_types=1);

namespace Bastion\Http\Middleware;

use ParagonIE\CSPBuilder\CSPBuilder;
use Psr\Http\Message\{ResponseInterface, ServerRequestInterface};
use Psr\Http\Server\{MiddlewareInterface, RequestHandlerInterface};

/**
 * Заголовки безопасности (ADR-0015). Строгий CSP без inline-скриптов и стилей:
 * весь JS/CSS — только файлы с собственного origin.
 */
final class SecurityHeaders implements MiddlewareInterface
{
    public function __construct(private readonly bool $https)
    {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $response = $handler->handle($request);
        $csp = CSPBuilder::fromData((string) json_encode([
            'default-src' => ['self' => true],
            'script-src' => ['self' => true],
            'style-src' => ['self' => true],
            'img-src' => ['self' => true, 'data' => false],
            'object-src' => [],
            'base-uri' => [],
            'frame-ancestors' => [],
            'form-action' => ['self' => true],
            'upgrade-insecure-requests' => $this->https,
        ]));
        $response = $csp->injectCSPHeader($response)
            ->withHeader('X-Content-Type-Options', 'nosniff')
            ->withHeader('X-Frame-Options', 'DENY')
            ->withHeader('Referrer-Policy', 'same-origin')
            ->withHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()')
            ->withHeader('Cross-Origin-Opener-Policy', 'same-origin')
            ->withHeader('Cross-Origin-Resource-Policy', 'same-origin');
        if ($this->https) {
            $response = $response->withHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        }
        if (str_starts_with($request->getUri()->getPath(), '/admin') || str_starts_with($request->getUri()->getPath(), '/install')) {
            $response = $response->withHeader('Cache-Control', 'no-store');
        }
        return $response->withoutHeader('X-Powered-By');
    }
}
