<?php
declare(strict_types=1);

namespace Bastion\Tests\Support;

use Bastion\Extensions\Application\PackageSignature;

final class ExtensionFixtures
{
    public readonly string $secret;
    public readonly string $public;

    public function __construct()
    {
        $pair = sodium_crypto_sign_keypair();
        $this->secret = sodium_crypto_sign_secretkey($pair);
        $this->public = base64_encode(sodium_crypto_sign_publickey($pair));
    }

    /** @param list<string> $caps */
    public function manifest(string $version = '1.0.0', array $caps = ['render.helper'], string $name = 'acme/hello'): string
    {
        return json_encode(['name' => $name, 'version' => $version, 'publisher_key' => $this->public,
            'capabilities' => $caps, 'entry' => 'Plugin'], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }

    public static function plugin(string $body = "\$context->helpers()->add('shout', static fn (string \$s): string => mb_strtoupper(\$s) . '!');"): string
    {
        return "<?php\ndeclare(strict_types=1);\nnamespace BastionExt\\Acme\\Hello;\n\nuse Bastion\\Extension\\Api\\{Context, Extension};\n\n"
            . "final class Plugin implements Extension\n{\n    public function register(Context \$context): void\n    {\n        {$body}\n    }\n}\n";
    }

    /** @param array<string, string> $files */
    public static function zip(array $files): string
    {
        $tmp = (string) tempnam(sys_get_temp_dir(), 'extfx');
        $zip = new \ZipArchive();
        $zip->open($tmp, \ZipArchive::CREATE | \ZipArchive::OVERWRITE);
        foreach ($files as $name => $content) {
            $zip->addFromString($name, $content);
        }
        $zip->close();
        $bytes = (string) file_get_contents($tmp);
        unlink($tmp);
        return $bytes;
    }

    /** @return array{0: string, 1: string} zip, signature */
    public function package(?string $plugin = null, string $version = '1.0.0', array $caps = ['render.helper']): array
    {
        $zip = self::zip(['extension.json' => $this->manifest($version, $caps), 'src/Plugin.php' => $plugin ?? self::plugin()]);
        return [$zip, PackageSignature::sign($zip, $this->secret)];
    }
}
