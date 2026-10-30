<?php
declare(strict_types=1);

namespace Bastion\Tests\Attack;

use Bastion\SecurityMonitoring\Domain\{ActorKey, DetectionPoint, ResponseAction};
use Bastion\SecurityMonitoring\Infrastructure\DbAppSensor;
use Bastion\Tests\Support\{Database, FrozenClock};
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

/** Abuser stories: credential-stuffing, appsensor-lockout-abuse. */
final class AppSensorLockoutTest extends TestCase
{
    public function testFailedPasswordsLockAccountTemporarily(): void
    {
        $clock = new FrozenClock();
        $sensor = new DbAppSensor(Database::memory(), $clock, new NullLogger());
        $acct = ActorKey::account('owner');

        for ($i = 0; $i < 4; $i++) {
            $sensor->event(DetectionPoint::AE2, $acct);
        }
        self::assertFalse($sensor->isActive(ResponseAction::TemporaryLock, $acct));
        $sensor->event(DetectionPoint::AE2, $acct);
        self::assertTrue($sensor->isActive(ResponseAction::TemporaryLock, $acct));

        $clock->advance(901);
        self::assertFalse($sensor->isActive(ResponseAction::TemporaryLock, $acct), 'блокировка временная');
    }

    public function testAttackerCannotLockOwnerIpAndEmergencyClearWorks(): void
    {
        $sensor = new DbAppSensor(Database::memory(), new FrozenClock(), new NullLogger());
        $attackerIp = ActorKey::ip('203.0.113.9');
        $ownerIp = ActorKey::ip('198.51.100.1');
        $acct = ActorKey::account('owner');
        for ($i = 0; $i < 25; $i++) {
            $sensor->event(DetectionPoint::AE3, $attackerIp);
            $sensor->event(DetectionPoint::AE2, $acct);
        }
        self::assertTrue($sensor->isActive(ResponseAction::Throttle, $attackerIp));
        self::assertFalse($sensor->isActive(ResponseAction::Throttle, $ownerIp));

        $sensor->clear($acct);
        self::assertFalse($sensor->isActive(ResponseAction::TemporaryLock, $acct));
    }
}
