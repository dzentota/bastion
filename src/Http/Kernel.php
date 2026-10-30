<?php
declare(strict_types=1);

namespace Bastion\Http;

use Bastion\Content\Domain\{EntryId, Slug};
use Bastion\Content\Infrastructure\EntryRepository;
use Bastion\Content\Rendering\BlockHtmlRenderer;
use Bastion\Http\Controller\{AuthController, EntryController, InstallController, PublicController};
use Bastion\Http\Middleware\{AppSensorGate, ErrorHandler, InstallGuard, RequireStaff, SecurityHeaders, SessionCsrfStrategy};
use Bastion\IdentityAccess\Application\{PasswordVerifier, TwoStepLogin};
use Bastion\IdentityAccess\Infrastructure\AccountRepository;
use Bastion\Infrastructure\Database\{Connection, Tables};
use Bastion\Installation\{DbDriver, DbHost, DbName, Installer, Paths};
use Bastion\SecurityMonitoring\Domain\AppSensor;
use Bastion\SecurityMonitoring\Infrastructure\{DbAppSensor, LogOnlyAppSensor};
use Bastion\Shared\Infrastructure\{FileLogger, SystemClock};
use Bastion\Theming\Dsl\{DirectoryTemplateSource, Renderer, SignedAstCache, TrustedHtmlToken};
use DI\ContainerBuilder;
use dzentota\ConfigLoader\ConfigLoaderFactory;
use dzentota\Router\Middleware\CsrfMiddleware;
use dzentota\Router\Router;
use Dzentota\Session\Cookie\CookieManager;
use Dzentota\Session\Middleware\SessionMiddleware;
use Dzentota\Session\SessionEncryptor;
use Dzentota\Session\Storage\DatabaseStorage;
use Nyholm\Psr7\Factory\Psr17Factory;
use ParagonIE\Halite\KeyFactory;
use Psr\Clock\ClockInterface;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\{ResponseFactoryInterface, ResponseInterface, ServerRequestInterface};
use Psr\Log\LoggerInterface;
use SecureDb\Db;

use function DI\{create, factory, get};
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};

/**
 * Сборка приложения. PHP-DI без autowiring: весь граф зависимостей виден здесь (ADR-0006).
 *
 * Порядок middleware (снаружи внутрь):
 *   ErrorHandler → SecurityHeaders → InstallGuard → AppSensorGate → Session → CSRF → routing
 */
#[AssetId('bastion-app')]
final class Kernel
{
    private readonly ContainerInterface $c;

    public function __construct(Paths $paths, bool $https, bool $devCookies = false)
    {
        $this->c = self::container($paths, $https, $devCookies);
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        /** @var Router $router */
        $router = $this->c->get(Router::class);
        return $router->dispatch($request->getUri()->getPath(), $request->getMethod(), $request);
    }

    private static function container(Paths $paths, bool $https, bool $devCookies): ContainerInterface
    {
        $b = new ContainerBuilder();
        $b->useAutowiring(false);
        $b->useAttributes(false);
        $b->addDefinitions([
            Paths::class => $paths,
            Psr17Factory::class => create(Psr17Factory::class),
            ResponseFactoryInterface::class => get(Psr17Factory::class),
            ClockInterface::class => create(SystemClock::class),
            LoggerInterface::class => factory(fn () => new FileLogger($paths->var('log/security.log'))),

            Db::class => factory(function () use ($paths): Db {
                $cfg = ConfigLoaderFactory::createFromJsonAndEnv($paths->config(), 'BASTION_');
                if ($cfg->get('db.driver', DbDriver::class)->toNative() === 'mysql') {
                    return Connection::mysql(
                        $cfg->get('db.host', DbHost::class)->toNative(), (int) $cfg->getRaw('db.port'),
                        $cfg->get('db.name', DbName::class)->toNative(), $cfg->get('db.user', DbName::class)->toNative(),
                        (string) $cfg->getRaw('db.password'),
                    );
                }
                return Connection::sqlite($paths->sqlite());
            }),
            AppSensor::class => factory(fn (ContainerInterface $c) => $paths->isInstalled()
                ? new DbAppSensor($c->get(Db::class), $c->get(ClockInterface::class), $c->get(LoggerInterface::class))
                : new LogOnlyAppSensor($c->get(LoggerInterface::class))),
            AccountRepository::class => factory(fn (ContainerInterface $c) => new AccountRepository(
                $c->get(Db::class), KeyFactory::loadEncryptionKey($paths->encryptionKey()),
            )),
            EntryRepository::class => factory(fn (ContainerInterface $c) => new EntryRepository($c->get(Db::class))),
            TwoStepLogin::class => factory(fn (ContainerInterface $c) => new TwoStepLogin(
                new PasswordVerifier($c->get(AccountRepository::class)), $c->get(AccountRepository::class),
                $c->get(AppSensor::class), $c->get(ClockInterface::class),
            )),
            BlockHtmlRenderer::class => factory(fn () => new BlockHtmlRenderer(TrustedHtmlToken::issue())),
            View::class => factory(function (ContainerInterface $c) use ($paths): View {
                // До установки ключа кэша ещё нет — работаем без кэша AST.
                $cache = fn (string $sub) => is_file($paths->cacheKey())
                    ? new SignedAstCache(self::dir($paths->templateCache() . '/' . $sub), (string) file_get_contents($paths->cacheKey()))
                    : null;
                return new View(
                    new Renderer(new DirectoryTemplateSource($paths->adminTemplates()), $cache('admin')),
                    new Renderer(new DirectoryTemplateSource($paths->theme('default')), $cache('theme')),
                    $c->get(ResponseFactoryInterface::class),
                );
            }),
            Installer::class => create(Installer::class)->constructor(get(Paths::class)),

            PublicController::class => factory(fn (ContainerInterface $c) => new PublicController($c->get(EntryRepository::class), $c->get(BlockHtmlRenderer::class), $c->get(View::class))),
            InstallController::class => factory(fn (ContainerInterface $c) => new InstallController($c->get(Installer::class), $c->get(View::class), $c->get(AppSensor::class))),
            AuthController::class => factory(fn (ContainerInterface $c) => new AuthController($c->get(TwoStepLogin::class), $c->get(View::class))),
            EntryController::class => factory(fn (ContainerInterface $c) => new EntryController($c->get(EntryRepository::class), $c->get(View::class), $c->get(AppSensor::class), $c->get(ClockInterface::class))),

            Router::class => factory(fn (ContainerInterface $c) => self::router($c, $paths, $https, $devCookies)),
        ]);
        return $b->build();
    }

    private static function router(ContainerInterface $c, Paths $paths, bool $https, bool $devCookies): Router
    {
        $responses = $c->get(ResponseFactoryInterface::class);
        $router = new Router($c, $c->get(LoggerInterface::class));
        $router->setPropagateExceptions(true); // ошибки обработчиков видит наш ErrorHandler
        $router->middleware(
            new ErrorHandler($responses, $c->get(LoggerInterface::class)),
            new SecurityHeaders($https),
            new InstallGuard($paths, $responses),
        );

        if (!$paths->isInstalled()) {
            // До установки нет БД: сессия в памяти процесса, CSRF всё равно обязателен.
            $router->middleware(...self::sessionAndCsrf(new \Dzentota\Session\Storage\CacheStorage(new InstallSessionCache($paths)), $c, $devCookies, $c->get(AppSensor::class)));
            $router->get('/install', [InstallController::class, 'form']);
            $router->post('/install', [InstallController::class, 'submit']);
            return $router;
        }

        $db = $c->get(Db::class);
        $encryptor = new SessionEncryptor(substr(hash('sha256', (string) file_get_contents($paths->cacheKey()) . 'session', true), 0, 32));
        $storage = new DatabaseStorage($db->getPdo(), Tables::SESSIONS, [$encryptor, 'encrypt'], [$encryptor, 'decrypt']);
        $router->middleware(
            new AppSensorGate($c->get(AppSensor::class), $responses),
            ...self::sessionAndCsrf($storage, $c, $devCookies, $c->get(AppSensor::class)),
        );

        $router->get('/', [PublicController::class, 'home']);
        $router->get('/admin/login', [AuthController::class, 'form']);
        $router->post('/admin/login', [AuthController::class, 'submit']);
        $router->get('/admin/2fa', [AuthController::class, 'totpForm']);
        $router->post('/admin/2fa', [AuthController::class, 'totpSubmit']);
        $router->get('/admin/2fa/setup', [AuthController::class, 'enrollForm']);
        $router->post('/admin/2fa/setup', [AuthController::class, 'enrollSubmit']);
        $router->post('/admin/logout', [AuthController::class, 'logout']);

        $staff = new RequireStaff($c->get(AccountRepository::class), $responses);
        $router->get('/admin', [EntryController::class, 'index'])->middleware($staff);
        $router->get('/admin/entries/new', [EntryController::class, 'create'])->middleware($staff);
        $router->post('/admin/entries', [EntryController::class, 'store'])->middleware($staff);
        $router->get('/admin/entries/{id}/edit', [EntryController::class, 'edit'])->where(['id' => EntryId::class])->middleware($staff);
        $router->post('/admin/entries/{id}', [EntryController::class, 'update'])->where(['id' => EntryId::class])->middleware($staff);
        $router->post('/admin/entries/{id}/publish', [EntryController::class, 'publish'])->where(['id' => EntryId::class])->middleware($staff);

        $router->get('/{slug}', [PublicController::class, 'show'])->where(['slug' => Slug::class]);
        return $router;
    }

    /** @return list<\Psr\Http\Server\MiddlewareInterface> */
    #[AbuserStory('session-hijack')]
    #[Mitigation(cwe: 'CWE-614', description: '__Host- session cookie: Secure, HttpOnly, SameSite=Strict, encrypted DB storage, idle/absolute timeouts')]
    private static function sessionAndCsrf(\Dzentota\Session\Storage\SessionStorageInterface $storage, ContainerInterface $c, bool $devCookies, AppSensor $sensor): array
    {
        // __Host- cookie требует HTTPS. Для локальной разработки (BASTION_DEV=1) — обычное имя без Secure.
        $cookie = $devCookies ? new CookieManager('bastion_sid', false, true, 'Strict') : new CookieManager('__Host-bastion', true, true, 'Strict');
        return [
            new SessionMiddleware($storage, $cookie, 1800, 14400, false, true, false),
            new CsrfMiddleware(
                new SessionCsrfStrategy($sensor), $c->get(LoggerInterface::class), [], null,
                failureResponseFactory: static function () use ($c): \Psr\Http\Message\ResponseInterface {
                    $r = $c->get(ResponseFactoryInterface::class)->createResponse(403)->withHeader('Content-Type', 'text/plain; charset=utf-8');
                    $r->getBody()->write("The form has expired. Go back, reload the page and try again.\n");
                    return $r;
                },
            ),
        ];
    }

    private static function dir(string $d): string
    {
        if (!is_dir($d)) {
            mkdir($d, 0700, true);
        }
        return $d;
    }
}
