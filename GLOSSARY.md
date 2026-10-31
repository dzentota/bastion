# Bastion CMS — Glossary

Единый язык проекта. Термин из этого словаря = имя класса / доменного примитива в коде.
Если в коде появляется понятие, которого здесь нет, — сначала добавляем его сюда.

## Общие

| Термин | Значение |
|---|---|
| **Bastion** | Security-first CMS для аудитории WordPress; практическое доказательство AppSecManifesto. |
| **Domain Primitive** | Value Object (dzentota/typedvalue), который невозможно создать в невалидном состоянии. «Parse, don't validate». Сырые скаляры не пересекают границы контекстов. |
| **Bounded Context** | Модуль с собственной моделью, примитивами и фрагментом модели угроз (`threat-model/<context>.php`). |
| **Trust Boundary** | Граница доверия в модели угроз Hybridtm. Любой поток данных через неё объявляется `#[DataFlow]`. |
| **Abuser Story** | «Как <злоумышленник>, я хочу <действие>, чтобы <цель>». Пишется до кода; без `#[Mitigation]` CI падает. |
| **Attack Test** | Исполняемый тест, воспроизводящий Abuser Story; обязан проходить (атака отражена). |
| **Degraded Mode** | Явно включённый режим пониженной безопасности (например, локальное хранилище медиа). Всегда виден в админке и является сигналом AppSensor. |

## Identity & Access

| Термин | Значение |
|---|---|
| **Account** | Учётная запись в админке. Комментаторы аккаунтов не имеют. |
| **Role** | `Admin`, `Editor`, `Author`. Набор Capabilities. |
| **Capability** | Атомарное право (`content.publish`, `media.upload`, …). Проверяется везде, роль — только группировка. |
| **Second Factor** | Passkey (WebAuthn, предпочтительно) или TOTP. Обязателен для Admin и Editor. |
| **Split Token** | Токен из selector + verifier (verifier хранится хешем); для сброса пароля и remember-me. |
| **Emergency Access** | Аварийный вход админа через CLI / файл на сервере в обход блокировки AppSensor. |

## Content / Taxonomy

| Термин | Значение |
|---|---|
| **Entry** | Единица контента: `Post` или `Page`. |
| **Block** | Типизированный Value Object внутри Entry (`Paragraph`, `Heading`, `Image`, `Quote`, `List`, `Code`, …). Сырого HTML нет; HTML появляется только при рендере. |
| **Revision** | Неизменяемый снимок Entry. |
| **Slug** | Доменный примитив URL-идентификатора. |
| **Term** | Элемент таксономии: `Category` или `Tag` (`TermKind`); идентифицируется видом и Slug. До 5 рубрик и 15 тегов на Entry (`TermList`). |
| **PageNumber** | Доменный примитив номера страницы листинга, 1..50: глубокая пагинация невозможна по построению. |

## Updates

| Термин | Значение |
|---|---|
| **Update Ledger** | Локальная HMAC-защищённая реплика журнала Chronicle (`LedgerStore`). |
| **Ledger Record** | Подписанная запись журнала: `key-append`, `key-revoke`, `release` (`LedgerRecord`). |
| **Super Provider** | Ключ проекта Bastion, закреплённый в конфиге; может отозвать ключ любого издателя. |
| **Attestation** | Подтверждение релиза журналом: digest архива записан активным ключом издателя (`TrustState::attest`). |

## Media

| Термин | Значение |
|---|---|
| **Media Item** | Загруженный файл с системно сгенерированным именем. |
| **Storage Adapter** | `S3Compatible` (по умолчанию) или `Local` (Degraded Mode). |
| **Re-encoding** | Перекодирование изображения (удаляет EXIF, полиглоты). SVG запрещён. |

## Comments

| Термин | Значение |
|---|---|
| **Comment** | Анонимный комментарий; публикуется только после модерации. Текст — plain text примитив. |
| **Moderation Queue** | Очередь комментариев на проверку. |

## Theming / Extensions

| Термин | Значение |
|---|---|
| **Theme** | Разновидность Extension с единственным правом `render`. Состоит из шаблонов на Template DSL. |
| **Template DSL** | Logic-less язык шаблонов (`if`/`each`/`include` + whitelist хелперов). Компилируется в PHP, кэш подписан HMAC. |
| **Extension (Plugin)** | Расширение с манифестом прав. Получает только выданные Facades. |
| **Extension Manifest** | Декларация Capabilities расширения; принимается админом при установке. |
| **Facade** | Узкий интерфейс ядра, выдаваемый расширению по манифесту (нет глобального доступа к БД/ФС/HTTP). |
| **Static Gate** | Статическая проверка кода расширения при установке (запрещённые функции, include, eval…). |
| **Publisher Key** | Ключ ed25519 автора расширения, зарегистрированный в Chronicle (модель Gossamer). |
| **Chronicle** | Append-only журнал ключей издателей и хэшей релизов. |
| **Super Provider** | Ключ, которым можно отозвать Publisher Key. |

## Security Monitoring (AppSensor)

| Термин | Значение |
|---|---|
| **Detection Point** | Место в коде, фиксирующее подозрительное событие; код по OWASP AppSensor (`AE1`, `IE1`, `CIE1`…). |
| **Event** | Срабатывание Detection Point для пользователя/IP. |
| **Attack** | Превышение порога Events для Detection Point за окно времени. |
| **Response** | Реакция на Attack. Автоматические: `Log`, `Notify`, `Throttle`, `Captcha`, `Logout`, `TemporaryLock`. Только вручную: `PermanentBlock`, `DisableFunction`. |

## Audit / Installation

| Термин | Значение |
|---|---|
| **Audit Entry** | Неизменяемая запись о значимом действии (кто, что, когда, откуда). |
| **Installer** | Веб-установщик; самоотключается после завершения. |
| **Security Update** | Подписанный пакет обновления ядра; применяется автоматически по умолчанию. |
