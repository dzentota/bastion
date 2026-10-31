<?php
declare(strict_types=1);

namespace Bastion\Tests\Integration;

use Bastion\Http\Kernel;
use Bastion\Infrastructure\Database\Connection;
use Bastion\Tests\Support\HttpHarness;
use PHPUnit\Framework\TestCase;

/** Стартовое содержимое сайта из docs/site (ADR-0025) — на настоящих файлах репозитория. */
final class SiteImportTest extends TestCase
{
    public function testImportsRealSiteContentOnceAndNeverOverwrites(): void
    {
        $h = new HttpHarness();
        $h->installAndLogin(languages: 'en, ru');
        mkdir($h->paths->root . '/docs');
        symlink(dirname(__DIR__, 2) . '/docs/site', $h->paths->root . '/docs/site');
        $kernel = new Kernel($h->paths, false, true);

        $report = implode("\n", $kernel->importSite());
        self::assertSame(16, substr_count($report, 'created'), $report);
        self::assertStringNotContainsString('error', $report);

        $anon = $h->fresh();
        $install = (string) $anon->get('/en/installation')->getBody();
        self::assertStringContainsString('<a href="/en/docs">Documentation</a> ›', $install, 'родитель из шапки файла');
        self::assertStringContainsString('hreflang="ru" href="/ru/installation"', $install, 'перевод связан');
        self::assertStringContainsString('<code class="language-bash">shasum -a 256 -c', $install);
        self::assertStringContainsString('<th>Component</th>', $install);
        self::assertStringContainsString('class="tm tm-overview"', (string) $anon->get('/ru/security')->getBody(), 'встроенная модель угроз');
        preg_match('~<nav class="menu"[^>]*>(.*?)</nav>~s', (string) $anon->get('/ru')->getBody(), $menu);
        self::assertSame(3, substr_count($menu[1] ?? '', '<a '), 'меню языка: документация, безопасность, о проекте');

        Connection::sqlite($h->paths->sqlite())->query("UPDATE ?_entries SET title = 'Edited in CMS' WHERE slug = 'about' AND lang = 'en'");
        $again = implode("\n", $kernel->importSite());
        self::assertStringNotContainsString('created', $again);
        self::assertSame('Edited in CMS', Connection::sqlite($h->paths->sqlite())->selectCell("SELECT title FROM ?_entries WHERE slug = 'about' AND lang = 'en'"));
    }
}
