<?php
declare(strict_types=1);

namespace Bastion\ThreatModel\Infrastructure;

use Bastion\ThreatModel\Domain\{InvalidThreatModel, ThreatModelData};
use Psr\Log\LoggerInterface;

/** build/threat-model.json релиза. Нет файла или он не прошёл проверку — модели нет (а не ошибка 500). */
final class ThreatModelSource
{
    private ?ThreatModelData $data = null;
    private bool $loaded = false;

    public function __construct(private readonly string $file, private readonly LoggerInterface $logger)
    {
    }

    public function get(): ?ThreatModelData
    {
        if (!$this->loaded) {
            $this->loaded = true;
            if (is_file($this->file) && !is_link($this->file) && filesize($this->file) <= ThreatModelData::MAX_BYTES) {
                try {
                    $this->data = ThreatModelData::fromJson((string) file_get_contents($this->file));
                } catch (InvalidThreatModel $e) {
                    $this->logger->warning('Threat model export rejected: {reason}', ['reason' => $e->getMessage()]);
                }
            }
        }
        return $this->data;
    }
}
