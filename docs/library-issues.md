# Дефекты библиотек, найденные при dogfooding (ADR-0004)

Каждый пункт — задача в соответствующем репозитории. Обходной путь в Bastion помечен `TODO(<lib>)`.

| # | Библиотека | Проблема | Влияние | Обход в Bastion |
|---|---|---|---|---|
| 1 | identity | `Authenticator::login()` сразу аутентифицирует сессию; нет шага второго фактора / публичного `verify()` | MFA невозможен без обхода | `PasswordVerifier` использует одноразовую in-memory сессию |
| 2 | identity | `Authenticator` получает свой `SessionManager` в конструкторе, а `SessionMiddleware` создаёт новый на каждый запрос — запись идёт не в ту сессию | Вход «не сохраняется» | `Authenticator` строится на сессии запроса (`RequireStaff`) |
| 3 | identity | Заявлен PHP `^7.4`, код требует 8.x; README использует несуществующий `$router->group()` | Сломанная установка/документация | — |
| 4 | session | После `regenerateId()` старый ID 10 с остаётся валидным **с данными** | Окно для session fixation | Двойная регенерация (после пароля и после 2FA) |
| 5 | session | `DatabaseStorage::createTable()` — MySQL-only синтаксис (`INDEX` внутри `CREATE`), ошибка проглатывается | Не работает на SQLite | Таблица создаётся в `Schema` |
| 6 | session | Один CSRF-токен на сессию; каждый `generateCsrfToken()` перезаписывает предыдущий | Две вкладки ломают формы | Принято для среза |
| 7 | session | README: неверный порядок аргументов `CookieManager` | — | — |
| 8 | router | `SynchronizerTokenStrategy` требует атрибут `session_id`, который никто не ставит; токен только в заголовке ответа | Неприменимо к SSR-формам | `SessionCsrfStrategy` поверх `SessionManager` |
| 9 | router | `CsrfMiddleware` лимитирует по `REMOTE_ADDR`; ответ 403 всегда JSON | За прокси — общий лимит | — |
| 10 | router | Исключения в обработчике проглатываются `RouteDispatchMiddleware` (500 JSON) — внешний error handler их не видит | Разный формат ошибок | Логируются через переданный logger |
| 11 | secure-db | `PlaceholderProcessor` отвергает `NULL`-параметры (`isset`) | Нельзя записать NULL | Колонки с NULL пропускаются при записи |
| 12 | secure-db | `setIdentifierPrefix()` применяется к `?_name` только в сырых запросах, не в `insert/update/delete` | Несогласованный API | `Tables::*` с полными именами |
| 13 | template-variable | URL-контекст = `rawurlencode()` всей строки | Нельзя вывести href | Фильтр `url` в DSL |
| 14 | template-engine | Шаблоны — полный PHP, нет ограниченного режима; `if ($flag)` по обёрнутому значению всегда true | Не подходит для тем (ADR-0013) | Собственный DSL |
| 15 | typedvalue | `toNative()`/`validate($value)` без типов и generics | ~105 из 170 ошибок phpstan max (baseline) | Baseline |
| 16 | hybridtm | `bin/hybridtm` ищет autoload только как корневой проект | Не запускается из vendor | `bin/hybridtm` обёртка |
| 17 | hybridtm | `#[Mitigation]` без `#[AssetId]` на классе молча игнорируется | Ложное «uncovered» без объяснения | `#[AssetId]` на всех классах с mitigation |
| 18 | все | Нет тегированных релизов, зависимости `dev-master`/`dev-main` | Невоспроизводимые сборки | `composer.lock` в репозитории |
