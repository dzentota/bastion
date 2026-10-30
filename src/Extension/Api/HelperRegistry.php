<?php
declare(strict_types=1);

namespace Bastion\Extension\Api;

interface HelperRegistry
{
    /**
     * Регистрирует helper "{{ value | <vendor>_<name> }}". Имя автоматически получает префикс расширения.
     * Результат helper'а всегда экранируется ядром — вывести HTML расширение не может.
     *
     * @param \Closure(string): string $helper
     */
    public function add(string $name, \Closure $helper): void;
}
