<?php
declare(strict_types=1);

use Bastion\Http\Kernel;
use Bastion\Installation\Paths;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7Server\ServerRequestCreator;

require dirname(__DIR__) . '/vendor/autoload.php';

$dev = getenv('BASTION_DEV') === '1';
$https = !$dev || (($_SERVER['HTTPS'] ?? '') !== '' && $_SERVER['HTTPS'] !== 'off');

if (!$dev && !$https) {
    // ADR-0009: HTTPS обязателен.
    http_response_code(403);
    exit("Bastion requires HTTPS.\n");
}

$f = new Psr17Factory();
$request = (new ServerRequestCreator($f, $f, $f, $f))->fromGlobals();
$kernel = new Kernel(new Paths(dirname(__DIR__)), $https, $dev);
$response = $kernel->handle($request);

header_remove('X-Powered-By');
http_response_code($response->getStatusCode());
foreach ($response->getHeaders() as $name => $values) {
    foreach ($values as $value) {
        header("{$name}: {$value}", false);
    }
}
echo $response->getBody();

// Ответ уже у клиента — теперь медленная работа (отправка писем) не влияет на время ответа.
if (function_exists('fastcgi_finish_request')) {
    fastcgi_finish_request();
}
$kernel->terminate();
