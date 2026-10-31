<?php
declare(strict_types=1);

namespace Bastion\Http\Middleware;

use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};
use Psr\Http\Message\{ResponseFactoryInterface, ResponseInterface, ServerRequestInterface};
use Psr\Http\Server\{MiddlewareInterface, RequestHandlerInterface};

/**
 * Делит сайт на служебную зону (/admin, /install) и публичную. Сессия и CSRF работают только
 * в служебной: читатели не получают cookie, CDN может кэшировать страницы, а таблица сессий не
 * растёт от каждого посетителя. Публичная зона принимает только GET/HEAD и POST /comments
 * (защищён подписанной меткой времени) — новый публичный POST без CSRF не появится случайно.
 */
#[AssetId('bastion-app')]
#[AbuserStory('cdn-session-sharing')]
#[Mitigation(cwe: 'CWE-524', description: 'Public responses never carry Set-Cookie: sessions start only under /admin and /install, so a shared cache cannot store and replay a session cookie')]
#[Mitigation(cwe: 'CWE-352', description: 'Outside the staff area only GET/HEAD and the honeypot-protected POST /comments are accepted; any other method is refused with 405')]
final class StaffArea implements MiddlewareInterface
{
    private const STAFF_PREFIXES = ['/admin', '/install'];
    private const PUBLIC_POST = ['/comments'];

    /** @param list<MiddlewareInterface> $staffOnly сессия, CSRF — в этом порядке */
    public function __construct(private readonly array $staffOnly, private readonly ResponseFactoryInterface $responses)
    {
    }

    public static function isStaffPath(string $path): bool
    {
        foreach (self::STAFF_PREFIXES as $p) {
            if ($path === $p || str_starts_with($path, $p . '/')) {
                return true;
            }
        }
        return false;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $path = $request->getUri()->getPath();
        if (!self::isStaffPath($path)) {
            $method = $request->getMethod();
            if (!in_array($method, ['GET', 'HEAD'], true) && !($method === 'POST' && in_array($path, self::PUBLIC_POST, true))) {
                return $this->responses->createResponse(405)->withHeader('Allow', 'GET, HEAD');
            }
            return $handler->handle($request);
        }
        return $this->chain($this->staffOnly, $handler)->handle($request);
    }

    /** @param list<MiddlewareInterface> $mws */
    private function chain(array $mws, RequestHandlerInterface $last): RequestHandlerInterface
    {
        foreach (array_reverse($mws) as $mw) {
            $last = new class ($mw, $last) implements RequestHandlerInterface {
                public function __construct(private readonly MiddlewareInterface $mw, private readonly RequestHandlerInterface $next)
                {
                }

                public function handle(ServerRequestInterface $request): ResponseInterface
                {
                    return $this->mw->process($request, $this->next);
                }
            };
        }
        return $last;
    }
}
