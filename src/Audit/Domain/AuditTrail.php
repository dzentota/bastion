<?php
declare(strict_types=1);

namespace Bastion\Audit\Domain;

/** Порт журнала аудита. Только добавление — методов удаления и изменения нет намеренно. */
interface AuditTrail
{
    /**
     * @param string|null $actor  id аккаунта, 'cli' или 'system'
     * @param string|null $subject id затронутого объекта или код (например, точка обнаружения AppSensor)
     */
    public function record(AuditAction $action, ?string $actor, ?string $subject, string $ip): void;
}
