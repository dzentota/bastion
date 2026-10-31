<?php
declare(strict_types=1);

namespace Bastion\Tests\Support;

use Bastion\Http\Kernel;
use Bastion\Installation\Paths;
use Nyholm\Psr7\ServerRequest;
use Psr\Http\Message\ResponseInterface;

/** Прогоняет запросы через настоящий Kernel во временном корне, с cookie jar. */
final class HttpHarness
{
    public readonly Paths $paths;
    /** @var array<string, string> */
    private array $cookies = [];
    public ?ResponseInterface $last = null;
    public CapturingMailer $mailer;
    public string $ip = '198.51.100.10';
    public string $host = 'localhost';

    public function __construct()
    {
        $root = sys_get_temp_dir() . '/bastion-http-' . bin2hex(random_bytes(4));
        mkdir($root);
        $repo = dirname(__DIR__, 2);
        symlink($repo . '/templates', $root . '/templates');
        symlink($repo . '/themes', $root . '/themes');
        $this->paths = new Paths($root);
        $this->mailer = new CapturingMailer();
    }

    public function fresh(): self
    {
        $h = clone $this;
        $h->cookies = [];
        return $h;
    }

    public function get(string $path): ResponseInterface
    {
        return $this->send('GET', $path, []);
    }

    /** @param array<string, mixed> $form */
    public function post(string $path, array $form, bool $withToken = true): ResponseInterface
    {
        if ($withToken) {
            $form['_token'] = $this->token();
        }
        return $this->send('POST', $path, $form);
    }

    /** Multipart-загрузка одного файла в поле "file". */
    public function upload(string $path, string $bytes, string $clientName, string $clientType = 'image/jpeg', bool $withToken = true): ResponseInterface
    {
        $file = new \Nyholm\Psr7\UploadedFile(\Nyholm\Psr7\Stream::create($bytes), strlen($bytes), UPLOAD_ERR_OK, $clientName, $clientType);
        return $this->send('POST', $path, $withToken ? ['_token' => $this->token()] : [], ['file' => $file]);
    }

    /** @param array<string, array{0: string, 1: string}> $files поле => [содержимое, имя файла] */
    public function uploadMany(string $path, array $files): ResponseInterface
    {
        $uploaded = [];
        foreach ($files as $field => [$bytes, $name]) {
            $uploaded[$field] = new \Nyholm\Psr7\UploadedFile(\Nyholm\Psr7\Stream::create($bytes), strlen($bytes), UPLOAD_ERR_OK, $name, 'application/octet-stream');
        }
        return $this->send('POST', $path, ['_token' => $this->token()], $uploaded);
    }

    public function token(): string
    {
        preg_match('/name="_token" value="([^"]+)"/', (string) $this->last?->getBody(), $m);
        return $m[1] ?? '';
    }

    public function body(): string
    {
        return (string) $this->last?->getBody();
    }

    /**
     * @param array<string, mixed> $form
     * @param array<string, \Psr\Http\Message\UploadedFileInterface> $files
     */
    private function send(string $method, string $path, array $form, array $files = []): ResponseInterface
    {
        // Kernel создаётся на каждый запрос, как в настоящем PHP-FPM.
        $kernel = new Kernel($this->paths, false, true, [\Bastion\Mail\Mailer::class => $this->mailer]);
        $req = (new ServerRequest($method, 'http://' . $this->host . $path, [], null, '1.1', ['REMOTE_ADDR' => $this->ip]))
            ->withCookieParams($this->cookies)
            ->withParsedBody($method === 'POST' ? $form : null)
            ->withUploadedFiles($files);
        $res = $kernel->handle($req);
        $kernel->terminate();
        foreach ($res->getHeader('Set-Cookie') as $c) {
            [$pair] = explode(';', $c, 2);
            [$k, $v] = explode('=', $pair, 2);
            $this->cookies[$k] = urldecode($v);
        }
        if ($res->getHeaderLine('Content-Type') !== '' && str_contains($res->getHeaderLine('Content-Type'), 'html')) {
            $this->last = $res;
        }
        return $res;
    }

    /** Полная установка + вход админа с подключением TOTP. Возвращает секрет TOTP. */
    public function installAndLogin(string $user = 'owner', string $pass = 'correct horse battery staple', string $languages = 'en'): string
    {
        $this->get('/install');
        $this->post('/install', ['install_token' => trim((string) file_get_contents($this->paths->installToken())),
            'driver' => 'sqlite', 'username' => $user, 'password' => $pass, 'email' => $user . '@example.com', 'languages' => $languages]);
        $this->get('/admin/login');
        $this->post('/admin/login', ['username' => $user, 'password' => $pass]);
        $this->get('/admin/2fa/setup');
        preg_match('~<code>([A-Z2-7 ]+)</code>~', $this->body(), $m);
        $secret = str_replace(' ', '', $m[1]);
        $this->post('/admin/2fa/setup', ['code' => \OTPHP\TOTP::createFromSecret($secret)->now()]);
        return $secret;
    }
}
