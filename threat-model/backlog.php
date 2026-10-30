<?php // threat-model/backlog.php
declare(strict_types=1);

/**
 * Abuser Stories, чьи фичи ещё НЕ реализованы. Гейт CI (bin/threat-gate) пропускает только их.
 * Правило: история уходит из бэклога в том же PR, где появляется её фича вместе с #[Mitigation]
 * и тестом атаки. Гейт падает и в обратную сторону — если история из бэклога уже покрыта.
 */
return [
    'term-enumeration-dos',  // Taxonomy
    'update-hijack',         // Updates (Chronicle)
];
