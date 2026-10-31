<?php
declare(strict_types=1);

namespace Bastion\Http;

use Bastion\Content\Domain\{EntryId, Slug};
use Bastion\Content\Infrastructure\EntryRepository;
use Bastion\Content\Rendering\BlockHtmlRenderer;
use Bastion\Audit\Domain\AuditTrail;
use Bastion\Audit\Infrastructure\HmacAuditTrail;
use Bastion\Comments\Application\{CommentPolicy, PostComment};
use Bastion\Comments\Domain\{CommentAuthor, CommenterFingerprint, CommentId};
use Bastion\Comments\Infrastructure\CommentRepository;
use Bastion\IdentityAccess\Application\PasswordReset;
use Bastion\IdentityAccess\Domain\{SiteUrl, StaffEmail};
use Bastion\IdentityAccess\Infrastructure\ResetTokenRepository;
use Bastion\Mail\{Mailer, SmtpConfig, SmtpMailer, UnconfiguredMailer};
use Bastion\Shared\Application\AfterResponse;
use Bastion\Extensions\Application\{ExtensionInstaller, ExtensionLoader, HelperCollector, PackageReader, StaticGate};
use Bastion\Taxonomy\Infrastructure\TermRepository;
use Bastion\Extensions\Infrastructure\{ExtensionRegistry, PublishedContentReader};
use Bastion\Http\Controller\{AuditController, AuthController, ExtensionController, PasswordResetController, CommentController, EntryController, TermController, InstallController, MediaController, PublicController};
use dzentota\Router\Middleware\HoneypotMiddleware;
use Bastion\Media\Application\{MediaSanitizer, UploadMedia, UploadPolicy};
use Bastion\Media\Domain\{MediaId, MediaStorage};
use Bastion\Media\Infrastructure\{LocalMediaStorage, MediaRepository, S3Config, S3MediaStorage};
use Dzentota\HttpClient\HttpClient;
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

    /** @param array<string, mixed> $overrides подмена сервисов (только для тестов) */
    public function __construct(Paths $paths, bool $https, bool $devCookies = false, array $overrides = [])
    {
        $this->c = self::container($paths, $https, $devCookies, $overrides);
    }

    /** Отложенная работа после отправки ответа (письма) — вызывается из public/index.php. */
    public function terminate(): void
    {
        $log = self::get($this->c, LoggerInterface::class);
        self::get($this->c, AfterResponse::class)->run(static fn (\Throwable $e) => $log->error('after_response.failed', ['type' => $e::class]));
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        /** @var Router $router */
        $router = $this->c->get(Router::class);
        return $router->dispatch($request->getUri()->getPath(), $request->getMethod(), $request);
    }

    /** @param array<string, mixed> $overrides */
    private static function container(Paths $paths, bool $https, bool $devCookies, array $overrides): ContainerInterface
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
                ? new DbAppSensor(self::get($c, Db::class), self::get($c, ClockInterface::class), self::get($c, LoggerInterface::class), self::get($c, AuditTrail::class))
                : new LogOnlyAppSensor(self::get($c, LoggerInterface::class))),
            AccountRepository::class => factory(fn (ContainerInterface $c) => new AccountRepository(
                self::get($c, Db::class), KeyFactory::loadEncryptionKey($paths->encryptionKey()),
            )),
            AfterResponse::class => create(AfterResponse::class),
            ExtensionRegistry::class => factory(fn (ContainerInterface $c) => new ExtensionRegistry(self::get($c, Db::class), self::derivedKey($paths, 'extensions'))),
            ExtensionInstaller::class => factory(fn (ContainerInterface $c) => new ExtensionInstaller(
                new PackageReader(), new StaticGate(), self::get($c, ExtensionRegistry::class), $paths->extensions(), self::get($c, AuditTrail::class),
            )),
            ExtensionController::class => factory(fn (ContainerInterface $c) => new ExtensionController(
                self::get($c, ExtensionInstaller::class), self::get($c, ExtensionRegistry::class), self::get($c, View::class), self::get($c, AppSensor::class),
            )),
            // helper'ы расширений для темы; расширения загружаются (с проверкой целостности) один раз на запрос
            HelperCollector::class => factory(function (ContainerInterface $c) use ($paths): HelperCollector {
                $helpers = new HelperCollector(self::get($c, LoggerInterface::class));
                if ($paths->isInstalled()) {
                    (new ExtensionLoader(
                        self::get($c, ExtensionRegistry::class), self::get($c, ExtensionInstaller::class), $helpers,
                        new PublishedContentReader(self::get($c, EntryRepository::class)), self::get($c, AppSensor::class), self::get($c, LoggerInterface::class),
                    ))->loadEnabled();
                }
                return $helpers;
            }),
            Mailer::class => factory(function () use ($paths): Mailer {
                $cfg = ConfigLoaderFactory::createFromJsonAndEnv($paths->config(), 'BASTION_', false);
                if (!is_string($cfg->getRaw('mail.host', null))) {
                    return new UnconfiguredMailer();
                }
                $raw = static fn (string $k): string => is_string($v = $cfg->getRaw($k)) ? $v : throw new \UnexpectedValueException("Config {$k} must be a string");
                return new SmtpMailer(new SmtpConfig(
                    $raw('mail.host'), (int) $raw('mail.port'), $raw('mail.user'), $raw('mail.password'),
                    StaffEmail::fromInput($raw('mail.from')) ?? throw new \UnexpectedValueException('Config mail.from must be an email'),
                ));
            }),
            PasswordReset::class => factory(function (ContainerInterface $c) use ($paths): PasswordReset {
                $cfg = ConfigLoaderFactory::createFromJsonAndEnv($paths->config(), 'BASTION_', false);
                return new PasswordReset(
                    self::get($c, AccountRepository::class), new ResetTokenRepository(self::get($c, Db::class)),
                    self::get($c, Mailer::class), self::get($c, AfterResponse::class),
                    SiteUrl::fromNative($cfg->getRaw('site.url')), self::get($c, AppSensor::class),
                    self::get($c, AuditTrail::class), self::get($c, ClockInterface::class),
                );
            }),
            PasswordResetController::class => factory(fn (ContainerInterface $c) => new PasswordResetController(
                self::get($c, PasswordReset::class), self::get($c, View::class),
            )),
            HmacAuditTrail::class => factory(fn (ContainerInterface $c) => new HmacAuditTrail(
                self::get($c, Db::class), self::derivedKey($paths, 'audit'), $paths->auditAnchor(), self::get($c, ClockInterface::class),
            )),
            AuditTrail::class => get(HmacAuditTrail::class),
            AuditController::class => factory(fn (ContainerInterface $c) => new AuditController(
                self::get($c, HmacAuditTrail::class), self::get($c, View::class), self::get($c, AppSensor::class),
            )),
            MediaRepository::class => factory(fn (ContainerInterface $c) => new MediaRepository(self::get($c, Db::class))),
            UploadPolicy::class => create(UploadPolicy::class),
            MediaStorage::class => factory(function (ContainerInterface $c) use ($paths): MediaStorage {
                $cfg = ConfigLoaderFactory::createFromJsonAndEnv($paths->config(), 'BASTION_', false);
                if ($cfg->getRaw('media.driver', 'local') !== 's3') {
                    return new LocalMediaStorage($paths->var()); // Degraded Mode (ADR-0011)
                }
                $raw = static fn (string $k): string => is_string($v = $cfg->getRaw($k)) ? $v : throw new \UnexpectedValueException("Config {$k} must be a string");
                $s3 = new S3Config($raw('media.endpoint'), $raw('media.region'), $raw('media.bucket'), $raw('media.access_key'), $raw('media.secret_key'));
                $f = self::get($c, Psr17Factory::class);
                $http = HttpClient::create();
                $http->setTimeout(15);
                return new S3MediaStorage($s3, $http, $f, $f, self::get($c, ClockInterface::class));
            }),
            UploadMedia::class => factory(fn (ContainerInterface $c) => new UploadMedia(
                new MediaSanitizer(self::get($c, UploadPolicy::class)), self::get($c, MediaStorage::class), self::get($c, MediaRepository::class),
                self::get($c, UploadPolicy::class), self::get($c, AppSensor::class), self::get($c, ClockInterface::class), self::get($c, LoggerInterface::class),
                self::get($c, AuditTrail::class),
            )),
            MediaController::class => factory(fn (ContainerInterface $c) => new MediaController(
                self::get($c, UploadMedia::class), self::get($c, MediaRepository::class), self::get($c, MediaStorage::class),
                self::get($c, View::class), self::get($c, ResponseFactoryInterface::class),
            )),
            EntryRepository::class => factory(fn (ContainerInterface $c) => new EntryRepository(self::get($c, Db::class))),
            TwoStepLogin::class => factory(fn (ContainerInterface $c) => new TwoStepLogin(
                new PasswordVerifier(self::get($c, AccountRepository::class)), self::get($c, AccountRepository::class),
                self::get($c, AppSensor::class), self::get($c, ClockInterface::class), self::get($c, AuditTrail::class),
            )),
            BlockHtmlRenderer::class => factory(fn () => new BlockHtmlRenderer(TrustedHtmlToken::issue())),
            View::class => factory(function (ContainerInterface $c) use ($paths): View {
                // До установки ключа кэша ещё нет — работаем без кэша AST.
                $cache = fn (string $sub) => is_file($paths->cacheKey())
                    ? new SignedAstCache(self::dir($paths->templateCache() . '/' . $sub), (string) file_get_contents($paths->cacheKey()))
                    : null;
                return new View(
                    new Renderer(new DirectoryTemplateSource($paths->adminTemplates()), $cache('admin')),
                    new Renderer(new DirectoryTemplateSource($paths->theme('default')), $cache('theme'), self::get($c, HelperCollector::class)->all()),
                    self::get($c, ResponseFactoryInterface::class),
                );
            }),
            Installer::class => create(Installer::class)->constructor(get(Paths::class)),

            PublicController::class => factory(fn (ContainerInterface $c) => new PublicController(
                self::get($c, EntryRepository::class), self::get($c, BlockHtmlRenderer::class), self::get($c, View::class),
                self::get($c, CommentRepository::class), self::get($c, HoneypotMiddleware::class), self::get($c, TermRepository::class),
            )),
            CommentRepository::class => factory(fn (ContainerInterface $c) => new CommentRepository(self::get($c, Db::class))),
            // Анонимная форма: подписанная метка времени + поле-ловушка (dzentota/router).
            // Лимит частоты считает PostComment по хэшу IP в БД, поэтому резолвер IP отключает
            // in-memory лимит middleware (бесполезный под PHP-FPM).
            HoneypotMiddleware::class => factory(fn (ContainerInterface $c) => new HoneypotMiddleware(
                ['website'], 3, false, self::get($c, LoggerInterface::class), null, 5,
                self::derivedKey($paths, 'honeypot'), 6 * 3600, static fn (): ?string => null,
            )),
            PostComment::class => factory(fn (ContainerInterface $c) => new PostComment(
                self::get($c, CommentRepository::class),
                new CommenterFingerprint(self::derivedKey($paths, 'comment-fingerprint')),
                new CommentPolicy(), self::get($c, AppSensor::class), self::get($c, ClockInterface::class),
                array_values(array_map(
                    static fn (string $n) => CommentAuthor::fromNative($n)->comparisonKey(),
                    array_merge(['admin', 'administrator', 'moderator', 'owner', 'editor', 'staff', 'support', 'bastion'],
                        self::get($c, AccountRepository::class)->usernames()),
                )),
            )),
            CommentController::class => factory(fn (ContainerInterface $c) => new CommentController(
                self::get($c, PostComment::class), self::get($c, CommentRepository::class), self::get($c, EntryRepository::class),
                self::get($c, PublicController::class), self::get($c, View::class), self::get($c, AppSensor::class),
                self::get($c, AuditTrail::class),
            )),
            InstallController::class => factory(fn (ContainerInterface $c) => new InstallController(self::get($c, Installer::class), self::get($c, View::class), self::get($c, AppSensor::class))),
            AuthController::class => factory(fn (ContainerInterface $c) => new AuthController(self::get($c, TwoStepLogin::class), self::get($c, View::class))),
            EntryController::class => factory(fn (ContainerInterface $c) => new EntryController(self::get($c, EntryRepository::class), self::get($c, View::class), self::get($c, AppSensor::class), self::get($c, ClockInterface::class), self::get($c, MediaRepository::class), self::get($c, AuditTrail::class), self::get($c, TermRepository::class))),
            TermRepository::class => factory(fn (ContainerInterface $c) => new TermRepository(self::get($c, Db::class))),
            TermController::class => factory(fn (ContainerInterface $c) => new TermController(
                self::get($c, TermRepository::class), self::get($c, EntryRepository::class), self::get($c, View::class), self::get($c, AppSensor::class),
            )),

            Router::class => factory(fn (ContainerInterface $c) => self::router($c, $paths, $https, $devCookies)),
        ]);
        $b->addDefinitions($overrides);
        return $b->build();
    }

    private static function router(ContainerInterface $c, Paths $paths, bool $https, bool $devCookies): Router
    {
        $responses = self::get($c, ResponseFactoryInterface::class);
        $router = new Router($c, self::get($c, LoggerInterface::class));
        $router->setPropagateExceptions(true); // ошибки обработчиков видит наш ErrorHandler
        $router->middleware(
            new ErrorHandler($responses, self::get($c, LoggerInterface::class)),
            new SecurityHeaders($https),
            new InstallGuard($paths, $responses),
        );

        if (!$paths->isInstalled()) {
            // До установки нет БД: сессия в памяти процесса, CSRF всё равно обязателен.
            $router->middleware(...self::sessionAndCsrf(new \Dzentota\Session\Storage\CacheStorage(new InstallSessionCache($paths)), $c, $devCookies, self::get($c, AppSensor::class)));
            $router->get('/install', [InstallController::class, 'form']);
            $router->post('/install', [InstallController::class, 'submit']);
            return $router;
        }

        $db = self::get($c, Db::class);
        $encryptor = new SessionEncryptor(substr(hash('sha256', (string) file_get_contents($paths->cacheKey()) . 'session', true), 0, 32));
        $storage = new DatabaseStorage($db->getPdo(), Tables::SESSIONS, [$encryptor, 'encrypt'], [$encryptor, 'decrypt']);
        $router->middleware(
            new AppSensorGate(self::get($c, AppSensor::class), $responses),
            ...self::sessionAndCsrf($storage, $c, $devCookies, self::get($c, AppSensor::class)),
        );

        $router->get('/', [PublicController::class, 'home']);
        $router->get('/admin/login', [AuthController::class, 'form']);
        $router->post('/admin/login', [AuthController::class, 'submit']);
        $router->get('/admin/2fa', [AuthController::class, 'totpForm']);
        $router->post('/admin/2fa', [AuthController::class, 'totpSubmit']);
        $router->get('/admin/2fa/setup', [AuthController::class, 'enrollForm']);
        $router->post('/admin/2fa/setup', [AuthController::class, 'enrollSubmit']);
        $router->post('/admin/logout', [AuthController::class, 'logout']);
        $router->get('/admin/forgot', [PasswordResetController::class, 'form']);
        $router->post('/admin/forgot', [PasswordResetController::class, 'request']);
        $router->get('/admin/reset/{token}', [PasswordResetController::class, 'arrive'])->where(['token' => \Bastion\IdentityAccess\Domain\ResetToken::class]);
        $router->get('/admin/reset', [PasswordResetController::class, 'choose']);
        $router->post('/admin/reset', [PasswordResetController::class, 'complete']);

        $staff = new RequireStaff(self::get($c, AccountRepository::class), $responses);
        $router->get('/admin', [EntryController::class, 'index'])->middleware($staff);
        $router->get('/admin/entries/new', [EntryController::class, 'create'])->middleware($staff);
        $router->post('/admin/entries', [EntryController::class, 'store'])->middleware($staff);
        $router->get('/admin/entries/{id}/edit', [EntryController::class, 'edit'])->where(['id' => EntryId::class])->middleware($staff);
        $router->post('/admin/entries/{id}', [EntryController::class, 'update'])->where(['id' => EntryId::class])->middleware($staff);
        $router->post('/admin/entries/{id}/publish', [EntryController::class, 'publish'])->where(['id' => EntryId::class])->middleware($staff);

        $router->get('/admin/media', [MediaController::class, 'index'])->middleware($staff);
        $router->post('/admin/media', [MediaController::class, 'store'])->middleware($staff);
        $router->get('/media/{id}', [MediaController::class, 'serve'])->where(['id' => MediaId::class]);

        $router->post('/comments', [CommentController::class, 'store'])->middleware(self::get($c, HoneypotMiddleware::class));
        $router->get('/admin/extensions', [ExtensionController::class, 'index'])->middleware($staff);
        $router->post('/admin/extensions', [ExtensionController::class, 'upload'])->middleware($staff);
        $router->post('/admin/extensions/enable', [ExtensionController::class, 'enable'])->middleware($staff);
        $router->post('/admin/extensions/disable', [ExtensionController::class, 'disable'])->middleware($staff);
        $router->get('/admin/audit', [AuditController::class, 'index'])->middleware($staff);
        $router->get('/admin/comments', [CommentController::class, 'queue'])->middleware($staff);
        foreach (['approve', 'reject', 'spam'] as $action) {
            $router->post("/admin/comments/{id}/{$action}", [CommentController::class, $action])->where(['id' => CommentId::class])->middleware($staff);
        }

        $router->get('/category/{slug}', [TermController::class, 'category'])->where(['slug' => Slug::class]);
        $router->get('/tag/{slug}', [TermController::class, 'tag'])->where(['slug' => Slug::class]);
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
                // /comments — анонимная форма без сессии: защищена подписанной меткой времени (HoneypotMiddleware).
                new SessionCsrfStrategy($sensor), self::get($c, LoggerInterface::class), ['/comments'], null,
                failureResponseFactory: static function () use ($c): \Psr\Http\Message\ResponseInterface {
                    $r = self::get($c, ResponseFactoryInterface::class)->createResponse(403)->withHeader('Content-Type', 'text/plain; charset=utf-8');
                    $r->getBody()->write("The form has expired. Go back, reload the page and try again.\n");
                    return $r;
                },
            ),
        ];
    }

    /**
     * Типизированный доступ к PSR-11 контейнеру: get() возвращает mixed.
     * @template T of object
     * @param class-string<T> $id
     * @return T
     */
    private static function get(ContainerInterface $c, string $id): object
    {
        $service = $c->get($id);
        return $service instanceof $id ? $service : throw new \LogicException("Container returned unexpected type for {$id}");
    }

    /** Отдельный ключ на каждое назначение, выведенный из мастер-ключа var/keys/cache.key. */
    private static function derivedKey(Paths $paths, string $purpose): string
    {
        return hash_hmac('sha256', 'bastion:' . $purpose, (string) file_get_contents($paths->cacheKey()), true);
    }

    private static function dir(string $d): string
    {
        if (!is_dir($d)) {
            mkdir($d, 0700, true);
        }
        return $d;
    }
}
