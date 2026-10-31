<?php
declare(strict_types=1);

namespace Bastion\Tests\Shared;

use Bastion\Content\Domain\Language;
use Bastion\Shared\I18n\StringCatalog;
use PHPUnit\Framework\TestCase;

/** Abuser story: catalog-injection — каталог остаётся данными. */
final class StringCatalogTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/bastion-catalog-' . bin2hex(random_bytes(4));
        mkdir($this->dir . '/admin', 0777, true);
        mkdir($this->dir . '/messages');
        file_put_contents($this->dir . '/admin/en.json', json_encode(['save' => 'Save', 'cancel' => 'Cancel']));
    }

    public function testTranslationOverridesEnglishAndFallsBack(): void
    {
        file_put_contents($this->dir . '/admin/ru.json', json_encode(['save' => 'Сохранить']));
        file_put_contents($this->dir . '/messages/ru.json', json_encode(['Invalid code.' => 'Неверный код.']));
        $c = new StringCatalog($this->dir);
        self::assertSame(['save' => 'Сохранить', 'cancel' => 'Cancel'], $c->strings('admin', Language::fromNative('ru')));
        self::assertSame('Неверный код.', $c->message('Invalid code.', Language::fromNative('ru')));
        self::assertSame('Other.', $c->message('Other.', Language::fromNative('ru')));
        self::assertSame(['en', 'ru'], array_map(static fn (Language $l) => $l->toNative(), $c->adminLanguages()));
        self::assertFalse($c->hasAdmin(Language::fromNative('de')));
    }

    public function testOnlyFlatStringJsonIsAccepted(): void
    {
        file_put_contents($this->dir . '/admin/ru.json', json_encode(['cancel' => 42, 'ok' => 'Ок', 'save' => null]));
        file_put_contents($this->dir . '/admin/kk.json', json_encode(['save' => ['nested' => 'x']]));
        file_put_contents($this->dir . '/admin/de.php', '<?php touch(' . var_export($this->dir . '/pwned', true) . '); return ["save" => "x"];');
        file_put_contents($this->dir . '/admin/uk.json', str_repeat(' ', 300000) . '{"save":"x"}');
        $c = new StringCatalog($this->dir);

        self::assertSame(['ok' => 'Ок', 'save' => 'Save', 'cancel' => 'Cancel'], $c->strings('admin', Language::fromNative('ru')));
        self::assertSame(['save' => 'Save', 'cancel' => 'Cancel'], $c->strings('admin', Language::fromNative('kk')), 'вложенные структуры — каталог отклонён целиком');
        self::assertSame(['save' => 'Save', 'cancel' => 'Cancel'], $c->strings('admin', Language::fromNative('de')), 'PHP-файл не подключается');
        self::assertFileDoesNotExist($this->dir . '/pwned');
        self::assertSame(['save' => 'Save', 'cancel' => 'Cancel'], $c->strings('admin', Language::fromNative('uk')), 'слишком большой каталог игнорируется');
        self::assertSame([], $c->strings('../admin', Language::fromNative('en')));
    }
}
