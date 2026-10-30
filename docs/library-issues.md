# Дефекты библиотек, найденные при dogfooding (ADR-0004)

Исправления — в ветках `fix/bastion-dogfooding` соответствующих репозиториев (пока не опубликованы).
Обходы в Bastion убраны в ветке `chore/library-fixes`.

| # | Библиотека | Проблема | Статус |
|---|---|---|---|
| 1 | identity | Нет шага второго фактора | ✅ `verifyCredentials()` + `completeLogin()` |
| 2 | identity | `Authenticator` писал в чужой `SessionManager` | ✅ сессия берётся из атрибута запроса |
| 3 | identity | PHP `^7.4`, README с несуществующим `$router->group()` | ✅ PHP ≥8.3, README исправлен |
| 4 | session | Старый ID 10 с валиден с данными после `regenerateId()` | ✅ tombstone без данных |
| 5 | session | `createTable()` только для MySQL, ошибка проглатывалась | ✅ mysql/sqlite/pgsql, `getLastError()` |
| 6 | session | Один CSRF-токен на сессию | ✅ пул из 10 токенов с TTL, `consumeCsrfToken()` |
| 7 | session | README: порядок аргументов `CookieManager` | ✅ |
| 8 | router | CSRF-стратегии непригодны для SSR-форм | ✅ `CsrfTokenProviderInterface`, атрибут `csrf_token`, резолвер session id |
| 9 | router | Лимит CSRF по `REMOTE_ADDR`, ответ только JSON | ✅ `clientIpResolver`, `failureResponseFactory` |
| 10 | router | Исключения обработчиков проглатывались | ✅ `Router::setPropagateExceptions()` |
| 11 | secure-db | `NULL`-параметры отвергались | ✅ |
| 12 | secure-db | Префикс не применялся в `insert/update/delete` | ✅ `?_name` в хелперах |
| 13 | template-variable | URL-контекст непригоден для href | ✅ `EscapeContext::URL_ATTR` (allowlist схем) |
| 14 | template-engine | `if ($flag)` всегда true | ✅ bool/null не оборачиваются, `isTruthy()`. Ограниченного режима нет — Bastion использует свой DSL (ADR-0013) |
| 15 | typedvalue | Нет generics | ✅ `@template`; baseline phpstan Bastion 170 → 123 |
| 16 | hybridtm | `bin/hybridtm` не работал из vendor | ✅ |
| 17 | hybridtm | `#[Mitigation]` без `#[AssetId]` молча игнорировался | ✅ учитывается через `#[AbuserStory]`, иначе предупреждение |
| 19 | http-client | **SSRF:** IP-литералы в URL (`https://127.0.0.1`, `10.x`, `2130706433`, `0x7f.1`) не проверялись по блоклисту — проверялся только результат DNS | ✅ dzentota/http-client#1 (плюс защита в `S3Config`) |
| 20 | router | `HoneypotMiddleware`: метка времени не подписана (подделывается или опускается), лимит частоты только в памяти (бесполезен под PHP-FPM), массив в поле-ловушке → TypeError | ⏳ ветка `fix/honeypot-signed-timestamp` (локально): подпись HMAC, `clientIpResolver` |
| 18 | все | Нет тегированных релизов | ⏳ после публикации веток |

Попутно: обновлены lock-файлы identity, session, secure-db — залоченные версии
sodium_compat, phpunit, php_codesniffer были под security advisories.
