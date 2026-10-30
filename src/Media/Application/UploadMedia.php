<?php
declare(strict_types=1);

namespace Bastion\Media\Application;

use Bastion\IdentityAccess\Domain\Account;
use Bastion\Media\Domain\{DisplayName, MediaId, MediaItem, MediaStorage, RejectedUpload};
use Bastion\Media\Infrastructure\MediaRepository;
use Bastion\SecurityMonitoring\Domain\{ActorKey, AppSensor, DetectionPoint};
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};
use Psr\Clock\ClockInterface;
use Psr\Http\Message\UploadedFileInterface;
use Psr\Log\LoggerInterface;

#[AssetId('bastion-app')]
#[AbuserStory('upload-flood')]
#[Mitigation(cwe: 'CWE-770', description: 'Per-account daily count and byte quotas; per-file size limit checked before reading; AppSensor FIO1/FIO2')]
final class UploadMedia
{
    public function __construct(
        private readonly MediaSanitizer $sanitizer,
        private readonly MediaStorage $storage,
        private readonly MediaRepository $media,
        private readonly UploadPolicy $policy,
        private readonly AppSensor $sensor,
        private readonly ClockInterface $clock,
        private readonly LoggerInterface $log,
    ) {
    }

    public function upload(Account $uploader, UploadedFileInterface $file): MediaItem
    {
        $actor = ActorKey::account($uploader->getId());
        if ($file->getError() !== UPLOAD_ERR_OK) {
            if (in_array($file->getError(), [UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE], true)) {
                $this->sensor->event(DetectionPoint::FIO1, $actor);
                throw new RejectedUpload(RejectedUpload::TOO_LARGE);
            }
            throw new RejectedUpload(RejectedUpload::UPLOAD_ERROR);
        }
        $size = $file->getSize();
        if ($size === null || $size > $this->policy->maxBytes) {
            $this->sensor->event(DetectionPoint::FIO1, $actor);
            throw new RejectedUpload(RejectedUpload::TOO_LARGE);
        }
        $now = $this->clock->now();
        $usage = $this->media->usageSince($uploader->getId(), $now->getTimestamp() - 86400);
        if ($usage['count'] >= $this->policy->maxUploadsPerDay || $usage['bytes'] + $size > $this->policy->maxBytesPerDay) {
            $this->sensor->event(DetectionPoint::FIO2, $actor);
            throw new RejectedUpload(RejectedUpload::QUOTA);
        }

        $stream = $file->getStream();
        $bytes = $stream->read($this->policy->maxBytes + 1);
        try {
            $clean = $this->sanitizer->sanitize($bytes);
        } catch (RejectedUpload $e) {
            $this->sensor->event(DetectionPoint::IE2, $actor);
            throw $e;
        }

        $item = new MediaItem(
            MediaId::generate(), $clean->kind, DisplayName::fromClient($file->getClientFilename()),
            strlen($clean->bytes), $clean->width, $clean->height, $uploader->getId(), $now,
        );
        $this->storage->put($item->key(), $clean->bytes, $item->kind);
        $this->media->add($item);
        if ($this->storage->isDegraded()) {
            $this->log->warning('media.degraded_storage', ['media' => $item->id->toNative()]);
        }
        return $item;
    }
}
