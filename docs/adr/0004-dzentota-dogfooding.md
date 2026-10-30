# ADR-0004: Библиотеки dzentota: dogfooding до 1.0

- Статус: принято
- Дата: 2026-10-30

## Контекст

Библиотеки dzentota не имеют тегированных релизов, зависят друг от друга через dev-master; identity допускает PHP ^7.4.

## Решение

Используем router (вкл. CSRF), session, identity, secure-db, config-loader, typedvalue/respected-typedvalue/DomainPrimitives, template-engine, template-variable, http-client, dns-resolver. Дефекты чиним в библиотеках. К MVP — релизы 1.0 и PHP 8.3+ везде.

## Последствия

Разработка CMS идёт параллельно с доводкой библиотек.
