<?php
declare(strict_types=1);

namespace Bastion\Updates\Infrastructure;

use Bastion\Updates\Application\UpdateTransport;
use Bastion\Updates\Domain\InvalidRecord;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;

/** HTTP только через dzentota/http-client (SSRF/DNS rebinding); размер ответа ограничен при чтении. */
final class HttpUpdateTransport implements UpdateTransport
{
    public function __construct(private readonly ClientInterface $http, private readonly RequestFactoryInterface $requests)
    {
    }

    public function get(string $url, int $maxBytes): array
    {
        $res = $this->http->sendRequest($this->requests->createRequest('GET', $url));
        $stream = $res->getBody();
        $body = '';
        while (!$stream->eof()) {
            $body .= $stream->read(65536);
            if (strlen($body) > $maxBytes) {
                throw new InvalidRecord('Response exceeds size limit');
            }
        }
        return ['status' => $res->getStatusCode(), 'body' => $body, 'signature' => $res->getHeaderLine('Body-Signature-Ed25519')];
    }
}
