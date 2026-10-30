<?php
declare(strict_types=1);

namespace Bastion\Infrastructure\Database;

/**
 * Имена таблиц. secure-db применяет префикс к ?_name только в сырых запросах,
 * но не в insert()/update()/delete() — поэтому полные имена для них берём отсюда.
 * TODO(secure-db): применять identifierPrefix единообразно.
 */
final class Tables
{
    public const PREFIX = 'bst_';
    public const ACCOUNTS = self::PREFIX . 'accounts';
    public const ENTRIES = self::PREFIX . 'entries';
    public const SECURITY_EVENTS = self::PREFIX . 'security_events';
    public const SECURITY_RESPONSES = self::PREFIX . 'security_responses';
    public const SESSIONS = self::PREFIX . 'sessions';
    public const AUDIT = self::PREFIX . 'audit';
}
