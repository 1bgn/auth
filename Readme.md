 Auth Service (Axum + MongoDB)

Сервис аутентификации на Rust: регистрация/логин, JWT (access/refresh), API keys (в отдельной коллекции), introspection и квоты (requests/minute + requests/day) по API key.

## Возможности

- JWT:
  - `access_token` для доступа к защищённым эндпоинтам.
  - `refresh_token` с **rotation**: старый refresh помечается `revoked_at`, также пишется `replaced_by`, есть защита от reuse (если пришёл уже revoked refresh — считаем компрометацией и отзываем активные refresh пользователя).
- API keys:
  - Отдельная коллекция `api_keys` (не в `users`).
  - Хранение `key_hash` (для проверки) + шифротекст ключа (для “reveal”).
  - `active`, `expires_at`, `scopes`.
- Quota/Rate limiting по API key:
  - `requests_per_minute` и `requests_per_day` + счётчики, обновляемые атомарно в MongoDB.
- Introspection:
  - `/auth/introspect` определяет тип токена (JWT access/refresh или api_key) и отвечает `active: true/false` в стиле RFC 7662. [page:6]
- Graceful shutdown:
  - Завершение по Ctrl+C/SIGTERM через `axum::serve(...).with_graceful_shutdown(...)`.

## Быстрый старт

### Требования
- Rust (stable)
- MongoDB

### Конфигурация
Создай `.env` (или прокинь переменные окружения):

```env
MONGODB_URI=mongodb://localhost:27017
DB_NAME=auth

JWT_SECRET=change-me
JWT_ACCESS_TTL_SECONDS=900
JWT_REFRESH_TTL_SECONDS=2592000

# Для шифрования plaintext API key (примерно 32 байта в base64/hex — как у тебя реализовано)
API_KEY_ENC_KEY=change-me
Запуск
bash
cargo run
API
Auth
POST /auth/register — регистрация, возвращает пользователя + токены + plaintext api_key (показывается один раз).

POST /auth/login — логин по email/password, возвращает токены.

GET /auth/me — текущий пользователь (Bearer access).

POST /auth/refresh — refresh rotation (новая пара токенов, старый refresh → revoked + replaced_by).

POST /auth/logout — отзывает refresh (идемпотентно).

Примеры:

bash
curl -X POST http://localhost:3000/auth/register \
  -H 'content-type: application/json' \
  -d '{"email":"a@b.com","name":"Alice","password":"secret"}'
bash
curl -X POST http://localhost:3000/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"a@b.com","password":"secret"}'
bash
curl http://localhost:3000/auth/me \
  -H "authorization: Bearer $ACCESS_TOKEN"
bash
curl -X POST http://localhost:3000/auth/refresh \
  -H 'content-type: application/json' \
  -d "{\"refresh_token\":\"$REFRESH_TOKEN\"}"
bash
curl -X POST http://localhost:3000/auth/logout \
  -H 'content-type: application/json' \
  -d "{\"refresh_token\":\"$REFRESH_TOKEN\"}"
API keys
POST /auth/api-key/rotate — ротация дефолтного ключа (Bearer access), возвращает новый plaintext ключ.

GET /auth/api-keys — список ключей пользователя (Bearer access).

bash
curl -X POST http://localhost:3000/auth/api-key/rotate \
  -H "authorization: Bearer $ACCESS_TOKEN"
bash
curl http://localhost:3000/auth/api-keys \
  -H "authorization: Bearer $ACCESS_TOKEN"
Introspection
POST /auth/introspect — принимает token (JWT или api key) и возвращает active + метаданные.

bash
curl -X POST http://localhost:3000/auth/introspect \
  -H 'content-type: application/json' \
  -d "{\"token\":\"$SOME_TOKEN\"}"
Ожидаемое поведение:

JWT access: active=true, token_type=access.

JWT refresh: active=true только если refresh найден в refresh_tokens, не revoked и не expired.

API key: active=true если ключ найден в api_keys (active, не истёк), token_type=api_key, опционально scopes.

Хранилище и важные детали
Коллекции
users: базовые поля пользователя + default_api_key_id.

refresh_tokens: token_hash, jti, revoked_at, replaced_by, expires_at.

api_keys: key_hash, active, expires_at, scopes, лимиты и счётчики usage.

Индексы (рекомендуется)
users.email unique

refresh_tokens.token_hash unique

refresh_tokens.jti unique

api_keys.key_hash unique

BSON Binary для ключей
Поля key_ciphertext и key_nonce нужно хранить как BSON Binary (а не Vec<u8> / [u8; 12]), чтобы doc!{ "$set": ... } корректно сериализовал байты и чтобы чтение/запись были стабильными.

Quota по API key
Квоты считаются по UTC-окнам:

minute bucket: requests_used_minute vs requests_per_minute

day bucket: requests_used_today vs requests_per_day
При превышении лимита сервис должен отвечать 429 Too Many Requests.

Graceful shutdown
Сервер обрабатывает Ctrl+C/SIGTERM и завершает приём новых соединений корректно (через .with_graceful_shutdown(...)), чтобы не ронять активные запросы.
