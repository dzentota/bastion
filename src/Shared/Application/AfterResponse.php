<?php
declare(strict_types=1);

namespace Bastion\Shared\Application;

/**
 * Работа, выполняемая после отправки ответа клиенту (fastcgi_finish_request).
 * Нужна, чтобы время ответа не зависело от медленных побочных эффектов,
 * например отправки письма (иначе — оракул существования аккаунта).
 */
final class AfterResponse
{
    /** @var list<\Closure(): void> */
    private array $tasks = [];

    /** @param \Closure(): void $task */
    public function defer(\Closure $task): void
    {
        $this->tasks[] = $task;
    }

    /** @param \Closure(\Throwable): void $onError */
    public function run(\Closure $onError): void
    {
        $tasks = $this->tasks;
        $this->tasks = [];
        foreach ($tasks as $task) {
            try {
                $task();
            } catch (\Throwable $e) {
                $onError($e);
            }
        }
    }
}
