<?php
declare(strict_types=1);

namespace Bastion\SecurityMonitoring\Domain;

/**
 * Точки обнаружения OWASP AppSensor (ADR-0010). Порог = событий за окно (сек) → ответ.
 * Коды — по каталогу OWASP AppSensor Detection Points.
 */
enum DetectionPoint: string
{
    case AE2 = 'AE2';   // Multiple failed passwords for one account
    case AE3 = 'AE3';   // High rate of login attempts from one source
    case AE12 = 'AE12'; // Utilization of common usernames / failed 2FA
    case IE1 = 'IE1';   // Cross-site scripting attempt in input
    case IE2 = 'IE2';   // Violation of implemented white lists (invalid domain primitive)
    case RE6 = 'RE6';   // POST without CSRF token / invalid token
    case ACE3 = 'ACE3'; // Force browsing attempt (forbidden admin action)
    case FIO1 = 'FIO1'; // Detect large individual file
    case FIO2 = 'FIO2'; // Detect large number of file uploads
    case UT2 = 'UT2';   // Speed of application use (comment bursts)
    case STE1 = 'STE1'; // Integrity violation: tampered template cache / installer probing

    /** @return array{threshold: int, window: int, response: ResponseAction, duration: int} */
    public function policy(): array
    {
        return match ($this) {
            self::AE2 => ['threshold' => 5, 'window' => 900, 'response' => ResponseAction::TemporaryLock, 'duration' => 900],
            self::AE3 => ['threshold' => 20, 'window' => 300, 'response' => ResponseAction::Throttle, 'duration' => 600],
            self::AE12 => ['threshold' => 5, 'window' => 900, 'response' => ResponseAction::Logout, 'duration' => 900],
            self::IE1 => ['threshold' => 3, 'window' => 3600, 'response' => ResponseAction::Throttle, 'duration' => 3600],
            self::IE2 => ['threshold' => 30, 'window' => 300, 'response' => ResponseAction::Throttle, 'duration' => 600],
            self::RE6 => ['threshold' => 5, 'window' => 600, 'response' => ResponseAction::Throttle, 'duration' => 600],
            self::ACE3 => ['threshold' => 3, 'window' => 600, 'response' => ResponseAction::Logout, 'duration' => 0],
            self::FIO1 => ['threshold' => 5, 'window' => 3600, 'response' => ResponseAction::Throttle, 'duration' => 3600],
            self::FIO2 => ['threshold' => 3, 'window' => 3600, 'response' => ResponseAction::Notify, 'duration' => 0],
            self::UT2 => ['threshold' => 3, 'window' => 3600, 'response' => ResponseAction::Throttle, 'duration' => 3600],
            self::STE1 => ['threshold' => 1, 'window' => 60, 'response' => ResponseAction::Notify, 'duration' => 0],
        };
    }
}
