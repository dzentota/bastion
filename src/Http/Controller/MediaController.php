<?php
declare(strict_types=1);

namespace Bastion\Http\Controller;

use Bastion\Http\Middleware\RequireStaff;
use Bastion\Http\View;
use Bastion\IdentityAccess\Domain\{Account, Capability};
use Bastion\Media\Application\UploadMedia;
use Bastion\Media\Domain\{MediaId, MediaItem, MediaNotFound, MediaStorage, RejectedUpload};
use Bastion\Media\Infrastructure\MediaRepository;
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};
use Psr\Http\Message\{ResponseFactoryInterface, ResponseInterface, ServerRequestInterface, UploadedFileInterface};

#[AssetId('bastion-app')]
final class MediaController
{
    public function __construct(
        private readonly UploadMedia $upload,
        private readonly MediaRepository $media,
        private readonly MediaStorage $storage,
        private readonly View $view,
        private readonly ResponseFactoryInterface $responses,
    ) {
    }

    public function index(ServerRequestInterface $request, ?string $error = null, int $status = 200): ResponseInterface
    {
        return $this->view->admin($request, 'media', [
            'items' => array_map(static fn (MediaItem $m) => [
                'url' => $m->url(), 'name' => $m->name, 'kind' => $m->kind->value, 'is_image' => $m->kind->isImage(),
                'size' => number_format($m->bytes / 1024, 0) . ' KB', 'id' => $m->id->toNative(),
            ], $this->media->latest(100)),
            'degraded' => $this->storage->isDegraded(),
            'error' => $error,
        ], $status);
    }

    public function store(ServerRequestInterface $request): ResponseInterface
    {
        $account = $request->getAttribute(RequireStaff::ACCOUNT);
        if (!$account instanceof Account || !$account->role->can(Capability::MediaUpload)) {
            return $this->view->admin($request, 'forbidden', [], 403);
        }
        $file = $request->getUploadedFiles()['file'] ?? null;
        if (!$file instanceof UploadedFileInterface) {
            return $this->index($request, 'Choose a file to upload.', 422);
        }
        try {
            $ip = $request->getServerParams()['REMOTE_ADDR'] ?? '';
            $this->upload->upload($account, $file, is_string($ip) ? $ip : 'unknown');
        } catch (RejectedUpload $e) {
            return $this->index($request, $e->userMessage(), 422);
        }
        return $this->view->redirect('/admin/media');
    }

    /**
     * Раздача медиа: тип только из MediaKind, nosniff, CSP sandbox без скриптов,
     * PDF — всегда вложение.
     */
    #[AbuserStory('media-content-sniffing')]
    #[Mitigation(cwe: 'CWE-79', description: 'Served with Content-Type from the sniffed kind, nosniff, CSP default-src none + sandbox; PDFs as attachment')]
    #[AbuserStory('media-path-traversal')]
    #[Mitigation(cwe: 'CWE-22', description: 'Files addressed only by MediaId (32 hex) mapped to a StorageKey; client file names never reach the filesystem')]
    public function serve(MediaId $id): ResponseInterface
    {
        $item = $this->media->find($id);
        try {
            $bytes = $item ? $this->storage->get($item->key()) : null;
        } catch (MediaNotFound) {
            $bytes = null;
        }
        if ($item === null || $bytes === null) {
            return $this->responses->createResponse(404);
        }
        $disposition = $item->kind->isImage() ? 'inline' : 'attachment';
        $r = $this->responses->createResponse(200)
            ->withHeader('Content-Type', $item->kind->mime())
            ->withHeader('Content-Length', (string) strlen($bytes))
            ->withHeader('Content-Disposition', $disposition . '; filename="' . $item->id->toNative() . '.' . $item->kind->extension() . '"')
            ->withHeader('Content-Security-Policy', "default-src 'none'; sandbox")
            ->withHeader('Cache-Control', 'public, max-age=31536000, immutable');
        $r->getBody()->write($bytes);
        return $r;
    }
}
