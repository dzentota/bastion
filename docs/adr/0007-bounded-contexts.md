# ADR-0007: Bounded contexts и доменные примитивы

- Статус: принято
- Дата: 2026-10-30

## Контекст

DDD + доменные примитивы как основа безопасности (правило 3 манифеста).

## Решение

Контексты: Identity & Access, Content, Taxonomy, Media, Comments, Theming, Extensions, Security Monitoring, Installation & Configuration, Audit. Сырые скаляры не пересекают границы контекстов. Контент — типизированные блоки, сырого HTML нет.

## Последствия

Каждый контекст имеет свой фрагмент модели угроз.
