<?php
declare(strict_types=1);

namespace Bastion\Tests\Attack\Media;

use Bastion\IdentityAccess\Domain\{Account, AccountId, Role, Username};
use Bastion\Media\Application\{MediaSanitizer, UploadMedia, UploadPolicy};
use Bastion\Media\Domain\RejectedUpload;
use Bastion\Media\Infrastructure\{LocalMediaStorage, MediaRepository};
use Bastion\SecurityMonitoring\Infrastructure\DbAppSensor;
use Bastion\Tests\Support\{Database, FrozenClock, MediaFixtures};
use Nyholm\Psr7\{Stream, UploadedFile};
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

/** Abuser story: upload-flood. */
final class UploadFloodTest extends TestCase
{
    public function testDailyQuotaStopsFlooding(): void
    {
        $db = Database::memory();
        $clock = new FrozenClock();
        $policy = new UploadPolicy(maxUploadsPerDay: 3);
        $dir = sys_get_temp_dir() . '/bastion-media-' . bin2hex(random_bytes(4));
        $upload = new UploadMedia(new MediaSanitizer($policy), new LocalMediaStorage($dir), new MediaRepository($db),
            $policy, new DbAppSensor($db, $clock, new NullLogger()), $clock, new NullLogger(), new \Bastion\Tests\Support\RecordingAuditTrail());
        $author = new Account(AccountId::generate(), Username::fromNative('writer'), Role::Author, false);
        $file = static fn () => new UploadedFile(Stream::create($b = MediaFixtures::image()), strlen($b), UPLOAD_ERR_OK, 'a.jpg', 'image/jpeg');

        for ($i = 0; $i < 3; $i++) {
            $upload->upload($author, $file());
        }
        try {
            $upload->upload($author, $file());
            self::fail('Quota not enforced');
        } catch (RejectedUpload $e) {
            self::assertSame(RejectedUpload::QUOTA, $e->reason);
        }
        $clock->advance(86401);
        $upload->upload($author, $file());
        self::assertCount(4, glob($dir . '/media/*/*.jpg') ?: []);
    }

    public function testDeclaredSizeOverLimitIsRejectedWithoutReading(): void
    {
        $db = Database::memory();
        $policy = new UploadPolicy(maxBytes: 1000);
        $upload = new UploadMedia(new MediaSanitizer($policy), new LocalMediaStorage(sys_get_temp_dir()), new MediaRepository($db),
            $policy, new DbAppSensor($db, new FrozenClock(), new NullLogger()), new FrozenClock(), new NullLogger(), new \Bastion\Tests\Support\RecordingAuditTrail());
        $author = new Account(AccountId::generate(), Username::fromNative('writer'), Role::Author, false);
        $this->expectException(RejectedUpload::class);
        $upload->upload($author, new UploadedFile(Stream::create('x'), 5_000_000, UPLOAD_ERR_OK, 'big.jpg', 'image/jpeg'));
    }
}
