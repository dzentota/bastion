<?php
declare(strict_types=1);

namespace Bastion\Infrastructure\Database\Migrations;

use SecureDb\Db;

/** i18n админки: язык интерфейса на пользователя (NULL — язык сайта по умолчанию). */
final class M0003AccountLocale implements Migration
{
    public function id(): string
    {
        return '0003_account_locale';
    }

    public function statements(string $driver): array
    {
        return ['ALTER TABLE ?_accounts ADD COLUMN locale VARCHAR(8) NULL'];
    }

    public function apply(Db $db, string $driver): void
    {
        foreach ($this->statements($driver) as $sql) {
            $db->query($sql);
        }
    }
}
