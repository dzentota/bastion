# Запуск сайта на VPS

Пошаговое руководство для оператора: сайт документации Bastion на собственном сервере, при желании — за CDN (ADR-0025). Команды — для Debian 12 / Ubuntu 24.04; `docs.example.org` замените своим доменом.

## Что получится

```
посетитель ─HTTPS─▶ [CDN, необязательно] ─HTTPS─▶ nginx ─FastCGI─▶ PHP-FPM (пользователь bastion)
                                                    │                  │
                                         /srv/bastion/current/public   /srv/bastion/shared/var
                                         (только чтение)               (БД, ключи, журнал — 0700)
```

Публичные страницы не ставят cookie и отдаются с `Cache-Control: public, max-age=60, s-maxage=300`; `/admin` и `/install` — `no-store`, с сессией.

## 1. Сервер

```bash
sudo apt install nginx php8.3-fpm php8.3-sqlite3 php8.3-mbstring php8.3-xml php8.3-curl sqlite3 unzip certbot python3-certbot-nginx
php -m | grep -E 'sodium|pdo_sqlite|mbstring'   # все три должны быть
sudo useradd --system --home /srv/bastion --shell /usr/sbin/nologin bastion
sudo mkdir -p /srv/bastion/releases /srv/bastion/shared/var /srv/bastion/shared/extensions
sudo chown -R bastion:bastion /srv/bastion/shared && sudo chmod 0700 /srv/bastion/shared/var
```

Пул PHP-FPM — `deploy/php-fpm-bastion.conf` → `/etc/php/8.3/fpm/pool.d/bastion.conf`. Веб-сервер — `deploy/nginx.conf` (или `deploy/Caddyfile`, если CDN не будет).

## 2. Выкладка релиза

Релиз собирается командой `bin/release X.Y.Z` (проверки, экспорт модели угроз, SBOM, zip и SHA-256).

```bash
cd /srv/bastion/releases
sudo -u bastion curl -fLO https://…/bastion-1.0.0.zip
sudo -u bastion curl -fLO https://…/bastion-1.0.0.zip.sha256
shasum -a 256 -c bastion-1.0.0.zip.sha256          # должно быть «OK»
sudo -u bastion unzip -q bastion-1.0.0.zip
cd bastion-1.0.0
sudo -u bastion rmdir var && sudo -u bastion ln -s /srv/bastion/shared/var var
sudo -u bastion ln -s /srv/bastion/shared/extensions extensions
sudo -u bastion php bin/sbom verify                 # vendor/, шрифты и экспорт модели угроз совпадают с SBOM
sudo chown -R root:bastion . && sudo find . -path ./var -prune -o -type d -exec chmod 0750 {} + -o -type f -exec chmod 0640 {} +
sudo ln -sfn /srv/bastion/releases/bastion-1.0.0 /srv/bastion/current
sudo systemctl reload php8.3-fpm
```

Код принадлежит root и только читается пользователем `bastion`; писать он может только в `shared/var` и `shared/extensions`.

## 3. Первая установка

1. Выпустите сертификат: `sudo certbot --nginx -d docs.example.org`, включите сайт nginx.
2. Откройте `https://docs.example.org/install`. Токен установки — в `/srv/bastion/shared/var/install.token`.
3. Языки: `en, ru` (первый — язык по умолчанию). Создайте администратора и подключите второй фактор.
4. В `var/config.json` в раздел `site` добавьте ссылку для сообщений о проблемах:
   ```json
   "issues_url": "https://github.com/<владелец>/<репозиторий>/issues"
   ```
5. Опубликуйте архитектурные решения: `sudo -u bastion php bin/bastion docs:sync-adr ru`.
6. Загрузите стартовое содержимое сайта: `sudo -u bastion php bin/bastion docs:import-site` (см. `docs/site/`). Страницы потом правятся в CMS.

## 4. CDN (необязательно)

- **Адреса клиентов.** За CDN `REMOTE_ADDR` — адрес узла CDN, и AppSensor блокировал бы узлы целиком. В `deploy/nginx.conf` раскомментируйте `set_real_ip_from` с диапазонами *вашего* CDN и `real_ip_header`. Никогда не доверяйте заголовку от произвольных адресов. Проверка: войдите в админку — в журнале аудита (`/admin/audit`) должен быть ваш настоящий IP.
- **Кэш.** Уважайте заголовки источника (`Cache-Control`). Не кэшируйте `/admin/*` и `/install*`, никогда не кэшируйте ответы с `Set-Cookie` (публичные страницы их не ставят — это страховка).
- **TLS до источника** — только HTTPS с проверкой сертификата («Full (strict)» и аналоги). Приложение отказывается работать по HTTP.
- **Закройте источник:** разрешите 443 только диапазонам CDN (и, если нужно, своему адресу для админки).
- После публикации страница обновится в CDN не позже чем через 5 минут; при необходимости — очистка кэша в панели CDN.

## 5. Обновление

Повторите шаг 2 для новой версии. Если в релизе есть миграции, публичный сайт до их применения отвечает 503: войдите в `/admin/database`, подтвердите кодом второго фактора — перед миграцией снимается резервная копия в `var/backups`. Откат — переключить `current` на прежний релиз и восстановить базу из этой копии.

## 6. Резервные копии и задания cron

`var/` — это всё состояние сайта: база, ключи (`var/keys`), якорь журнала аудита. Без ключей нельзя проверить журнал аудита и подписи ревизий — храните их копию отдельно от копии базы.

```cron
# /etc/cron.d/bastion
15 3 * * * bastion sqlite3 /srv/bastion/shared/var/bastion.sqlite ".backup '/srv/bastion/shared/var/backups/daily.sqlite'"
30 3 * * * bastion php /srv/bastion/current/bin/bastion audit:verify || echo "Bastion audit trail verification FAILED" | mail -s "bastion: audit" ops@example.org
*/30 * * * * bastion php /srv/bastion/current/bin/bastion updates:run   # только если настроен канал обновлений
```

Копии уносите с сервера зашифрованными (например, `restic` или `age`).

## 7. Проверка после запуска

```bash
curl -sI https://docs.example.org/en | grep -iE 'set-cookie|cache-control|content-security|strict-transport'
# ожидается: нет Set-Cookie; Cache-Control: public, max-age=60, s-maxage=300; CSP; HSTS
curl -sI https://docs.example.org/admin/login | grep -i cache-control      # no-store
curl -s -o /dev/null -w '%{http_code}\n' https://docs.example.org/../var/config.json   # 404, var/ недоступен
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://docs.example.org/en           # 405
sudo -u bastion php /srv/bastion/current/bin/sbom verify
```

И внешние проверки: TLS (SSL Labs), заголовки (securityheaders.com).
