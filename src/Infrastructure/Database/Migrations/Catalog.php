<?php
declare(strict_types=1);

namespace Bastion\Infrastructure\Database\Migrations;

use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};

/**
 * Полный список миграций — в коде, а не сканированием каталога: подброшенный на
 * хостинг файл не становится миграцией.
 */
#[AssetId('schema-migrator')]
#[AbuserStory('plant-migration')]
#[Mitigation(cwe: 'CWE-494', description: 'Migrations are an explicit class list compiled into the release, never discovered from the filesystem')]
final class Catalog
{
    /**
     * @param string $defaultLanguage язык сайта: им помечаются записи, созданные до i18n
     * @return list<Migration> по возрастанию id
     */
    public static function all(string $defaultLanguage = 'en'): array
    {
        return [
            new M0001Baseline(),
            new M0002EntryLanguages($defaultLanguage),
        ];
    }
}
