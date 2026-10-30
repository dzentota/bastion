<?php // threat-model/backlog.php
declare(strict_types=1);

/**
 * Abuser Stories, чьи фичи ещё НЕ реализованы. Гейт CI (bin/threat-gate) пропускает только их.
 * Правило: история уходит из бэклога в том же PR, где появляется её фича вместе с #[Mitigation]
 * и тестом атаки. Гейт падает и в обратную сторону — если история из бэклога уже покрыта.
 */
return [
    'reset-token-theft',     // Identity: сброс пароля (split-token)
    'term-enumeration-dos',  // Taxonomy
    'malicious-extension',   // Extensions (Static Gate + Gossamer)
    'capability-overreach',  // Extensions (Facades)
    'update-hijack',         // Updates (Chronicle)
    'audit-tamper',          // Audit (hash chain)
];
