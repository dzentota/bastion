<?php
declare(strict_types=1);

namespace Bastion\Extensions\Application;

use Bastion\Extension\Api\{CapabilityNotGranted, ContentReader, Context, HelperRegistry};
use Bastion\Extensions\Domain\{ExtCapability, InstalledExtension};
use Psr\Log\LoggerInterface;

/**
 * Фасады для одного расширения. Без public-свойств: приведение к массиву и foreach
 * ничего не раскрывают (а приведение запрещено ещё и Static Gate).
 */
final class ExtensionContext implements Context
{
    public function __construct(
        private readonly InstalledExtension $extension,
        private readonly HelperCollector $helpers,
        private readonly ContentReader $content,
        private readonly LoggerInterface $log,
    ) {
    }

    public function helpers(): HelperRegistry
    {
        $this->require(ExtCapability::RenderHelper);
        return $this->helpers->for($this->extension->manifest->name);
    }

    public function content(): ContentReader
    {
        $this->require(ExtCapability::ContentRead);
        return $this->content;
    }

    private function require(ExtCapability $cap): void
    {
        $name = $this->extension->manifest->name->toNative();
        if (!in_array($cap, $this->extension->granted, true)) {
            $this->log->warning('extension.capability_denied', ['extension' => $name, 'capability' => $cap->value]);
            throw new CapabilityNotGranted("{$name} was not granted {$cap->value}");
        }
        $this->log->info('extension.facade', ['extension' => $name, 'capability' => $cap->value]);
    }
}
