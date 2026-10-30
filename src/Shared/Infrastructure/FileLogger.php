<?php
declare(strict_types=1);

namespace Bastion\Shared\Infrastructure;

use Psr\Log\AbstractLogger;

/** JSON-lines лог безопасности (правило 8). Контекст логируется структурно; перевод строк вычищается (CWE-117). */
final class FileLogger extends AbstractLogger
{
    public function __construct(private readonly string $file)
    {
    }

    public function log($level, \Stringable|string $message, array $context = []): void
    {
        $dir = dirname($this->file);
        if (!is_dir($dir)) {
            @mkdir($dir, 0700, true);
        }
        $line = json_encode(['ts' => gmdate('c'), 'level' => $level, 'msg' => (string) $message, 'ctx' => $context],
            JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE);
        @file_put_contents($this->file, $line . "\n", FILE_APPEND | LOCK_EX);
    }
}
