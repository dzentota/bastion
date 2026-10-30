# ADR-0006: Приоритет библиотек: dzentota vs paragonie

- Статус: принято
- Дата: 2026-10-30

## Контекст

Пересечение функциональности dzentota и paragonie.

## Решение

dzentota — для всего, что у неё есть. paragonie — криптография (Halite, sodium, constant_time_encoding), цепочка поставок (Gossamer, Chronicle), CSP-builder. Прочие конфликты — отдельный ADR. Инфраструктура: nyholm/psr7 везде, PHP-DI без autowiring.

## Последствия

Явная конфигурация DI — больше кода, но полная прозрачность графа зависимостей.
