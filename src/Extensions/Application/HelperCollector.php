<?php
declare(strict_types=1);

namespace Bastion\Extensions\Application;

use Bastion\Extension\Api\HelperRegistry;
use Bastion\Extensions\Domain\ExtensionName;
use Psr\Log\LoggerInterface;

/** Собирает helper'ы расширений для Template DSL. Ошибка helper'а не роняет страницу. */
final class HelperCollector
{
    /** @var array<string, \Closure(string): string> */
    private array $helpers = [];

    public function __construct(private readonly LoggerInterface $log)
    {
    }

    public function for(ExtensionName $ext): HelperRegistry
    {
        $collector = $this;
        return new class ($collector, $ext) implements HelperRegistry {
            public function __construct(private readonly HelperCollector $collector, private readonly ExtensionName $ext)
            {
            }

            public function add(string $name, \Closure $helper): void
            {
                $this->collector->register($this->ext, $name, $helper);
            }
        };
    }

    /** @internal */
    public function register(ExtensionName $ext, string $name, \Closure $helper): void
    {
        if (!preg_match('/^[a-z][a-z0-9_]{0,31}$/', $name)) {
            throw new \InvalidArgumentException('Helper names: lowercase letters, digits, underscores');
        }
        $full = $ext->helperPrefix() . $name;
        $log = $this->log;
        $this->helpers[$full] = static function (string $value) use ($helper, $full, $log): string {
            try {
                $out = $helper($value);
                return is_string($out) ? $out : '';
            } catch (\Throwable $e) {
                $log->warning('extension.helper_failed', ['helper' => $full, 'type' => $e::class]);
                return '';
            }
        };
    }

    /** @return array<string, \Closure(string): string> */
    public function all(): array
    {
        return $this->helpers;
    }
}
