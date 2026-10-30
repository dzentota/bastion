# ADR-0010: AppSensor in-process по спецификации OWASP

- Статус: принято
- Дата: 2026-10-30

## Контекст

OWASP AppSensor; внешней платформы на shared-хостинге нет.

## Решение

Встроенный модуль: Detection Points с кодами OWASP, пороги на точку (значения по умолчанию — из ASRP). Автоматические Responses: Log, Notify, Throttle/Captcha, Logout, TemporaryLock. Только вручную: PermanentBlock, DisableFunction. Emergency Access через CLI/файл на сервере. Опциональный экспорт событий в ASRP.

## Последствия

Защита от самоблокировки обязательна.
