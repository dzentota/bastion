<?php
declare(strict_types=1);

namespace Bastion\Infrastructure\Database;

/**
 * Префикс таблиц. В запросах и в insert()/update()/delete() secure-db таблицы
 * указываются как ?_name; полное имя нужно только сторонним компонентам (сессии).
 */
final class Tables
{
    public const PREFIX = 'bst_';
    public const SESSIONS = self::PREFIX . 'sessions';
}
