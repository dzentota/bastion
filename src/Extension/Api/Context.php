<?php
declare(strict_types=1);

namespace Bastion\Extension\Api;

/** Фасады, выданные расширению по манифесту. Запрос невыданного права — CapabilityNotGranted. */
interface Context
{
    /** Право render.helper: регистрация helper'ов Template DSL. */
    public function helpers(): HelperRegistry;

    /** Право content.read: чтение опубликованных записей. */
    public function content(): ContentReader;
}
