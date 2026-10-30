# ADR-0008: Модель угроз до кода (Hybridtm) и CI-гейт

- Статус: принято
- Дата: 2026-10-30

## Контекст

Правило 7 манифеста.

## Решение

Корневой threat-model.php + фрагмент на контекст. Каждая фича начинается с Abuser Stories. CI: hybridtm analyze --fail-on-uncovered-stories. Каждая Abuser Story — Attack Test. TDD, phpstan max, infection.

## Последствия

PR без модели угроз не принимается.
