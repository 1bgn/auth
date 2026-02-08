Реализовано ядро auth‑сервиса и большая часть “production” фич, которые ты перечислял, но часть ещё в процессе интеграции/подгонки типов.

## Auth (JWT)
- Регистрация и логин: создание пользователя, хеширование пароля (Argon2) и выдача пары токенов (access/refresh).
- `/auth/me`: доступ по Bearer access JWT.
- Refresh rotation: при `/auth/refresh` старый refresh помечается `revoked_at`, добавлено поле `replaced_by`, и есть защита от reuse (если пришёл уже revoked refresh — отзываются активные refresh токены пользователя).

## API keys (отдельная коллекция)
- Ключи вынесены из `users` в отдельную коллекцию `api_keys` (хранение `key_hash`, `active`, `expires_at`, `scopes`, лимиты и счётчики).
- `reveal_api_key` расшифровывает и возвращает plaintext дефолтного ключа пользователя (если он есть).
- `rotate_default_api_key` генерирует новый plaintext ключ и обновляет запись ключа в базе (важно хранить байты как BSON `Binary`, а не `Vec<u8>`).

## Rate limit и квоты
- Реализована модель квот на API key: `requests_per_minute` и `requests_per_day` + счётчики `minute_bucket/requests_used_minute` и `usage_day/requests_used_today`.
- Логика квот рассчитана на атомарное потребление в MongoDB через `find_one_and_update` с update pipeline (это даёт реальную квоту, не только burst).

## Introspect
- Эндпоинт `/auth/introspect` реализован в стиле RFC 7662: ответ содержит `active` и для неактивного токена корректно возвращать `active=false` (обычно без лишних полей). [datatracker.ietf](https://datatracker.ietf.org/doc/html/rfc7662)
- Для JWT: access можно считать активным по успешной валидации JWT, для refresh добавлена проверка существования/отзыва в `refresh_tokens`.
- Для api key: проверка делается по `api_keys.key_hash` (а не по `users.api_key_hash`).

## Graceful shutdown
- Добавлен план/шаблон graceful shutdown через `tokio::signal::ctrl_c()` + `axum::serve(...).with_graceful_shutdown(...)` (если ты это уже вставил в `main.rs`, сервер будет корректно завершаться по Ctrl+C/SIGTERM).

Если хочешь, могу перечислить “реализовано” уже строго по файлам (что есть в `handlers`, что в `services`, что в `extractors`) — просто скажи структуру папок/модулей или скинь `lib.rs/main.rs` с `mod` и роутером.
