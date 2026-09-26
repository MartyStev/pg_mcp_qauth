# pg_mcp_qauth

Postgres **MCP-сервер** (Model Context Protocol) с OAuth 2.1 авторизацией для Claude Code.
Сервер работает как **OAuth Resource Server**: валидирует JWT, выдаваемый внешним
**Authorization Server** (Keycloak/Authentik), и выполняет только безопасные read-only
запросы к PostgreSQL с изоляцией прав на уровне ролей и RLS.

> **Статус:** beta. Проверено end-to-end на реальном Keycloak 26 + Postgres 16.
>
> **Возможности:** OAuth 2.1 resource server (RFC 9728) · мультипровайдер через брокер
> (Google / Entra ID / AD / Okta / GitHub) · трёхуровневый доступ (схема → таблица → строки/RLS) ·
> AST-based SQL guard · аудит-логирование · health-endpoint · Docker (non-root).

🇬🇧 English documentation: [README.md](README.md)

## Архитектура

- **Claude Code** — OAuth 2.1 client: получает access-токен у Authorization Server (PKCE).
- **Keycloak / Authentik** — единый Authorization Server и брокер. Мультипровайдерность
  (Google, Microsoft Entra ID, on-prem Active Directory, Okta, GitHub и т.д.) настраивается
  identity brokering'ом на стороне AS; код сервера всегда валидирует **один issuer**.
- **pg_mcp_qauth** — Resource Server (FastMCP, Streamable HTTP): отдаёт RFC 9728
  Protected Resource Metadata, возвращает `401 + WWW-Authenticate` без токена, валидирует
  подпись/`iss`/`aud`/`exp` через JWKS.
- **PostgreSQL** — запросы идут в транзакции `READ ONLY` c `SET LOCAL ROLE <role>` и
  session-GUC для RLS.

```
Claude Code --(OAuth PKCE)--> Keycloak/Authentik --(JWT)--> pg_mcp_qauth --> Postgres
                                   |  brokering
                                   +-> Google / Entra ID / AD / Okta / GitHub ...
```

## Модель доступа (три уровня)

| Уровень  | Механизм                       | Кто настраивает |
|----------|--------------------------------|-----------------|
| Схема    | `GRANT USAGE ON SCHEMA`        | DBA             |
| Таблица  | `GRANT SELECT` (или на вьюхи)  | DBA             |
| Строки   | RLS по session-GUC             | DBA             |

JWT-claim групп (`ROLES_CLAIM`) маппится в **DB-роль** через `ROLE_MAP_JSON`
(иначе `DEFAULT_ROLE`). Если пользователь входит в несколько смапленных групп,
**приоритет = порядок объявления ключей** в `ROLE_MAP_JSON` (первый совпавший выигрывает),
а не порядок групп в токене. Роль решает «какие таблицы видны», RLS — «какие строки видны
конкретному пользователю».

> **Keycloak:** роли по умолчанию лежат во вложенных claim'ах `realm_access.roles` /
> `resource_access.<client>.roles`. Сервер читает **плоский** claim, поэтому настройте
> protocol mapper, который кладёт группы/роли в плоский claim (например `groups`), и укажите
> его в `ROLES_CLAIM`.

`list_tables`, `describe_table` и `run_query` выполняются под `SET LOCAL ROLE` и дополнительно
проверяют `has_table_privilege(..., 'SELECT')` — структура таблиц, недоступных роли, не раскрывается.

### DBA-runbook (пример)

```sql
-- 1. Сервисный пользователь пула: НЕ superuser, НЕ владелец таблиц.
CREATE ROLE mcp_gateway LOGIN PASSWORD 'change-me';

-- 2. Роли-получатели прав.
CREATE ROLE read_analyst NOLOGIN;
CREATE ROLE read_marketing NOLOGIN;

-- 3. mcp_gateway должен уметь SET ROLE в целевые роли.
GRANT read_analyst, read_marketing TO mcp_gateway;

-- 4. Схема / таблицы.
GRANT USAGE ON SCHEMA analytics TO read_analyst;
GRANT SELECT ON ALL TABLES IN SCHEMA analytics TO read_analyst;
ALTER DEFAULT PRIVILEGES IN SCHEMA analytics GRANT SELECT ON TABLES TO read_analyst;

-- 5. Row Level Security по session-переменной, которую ставит MCP.
ALTER TABLE analytics.orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE analytics.orders FORCE ROW LEVEL SECURITY;
CREATE POLICY orders_by_region ON analytics.orders
  USING (region = current_setting('app.user_email', true));
```

> `current_setting('app.user_email', true)` / `app.groups` устанавливаются сервером через
> `set_config(..., true)` в рамках транзакции и не «протекают» на соединения пула.

## Запуск

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"        # или pip install -r requirements.lock для точных версий
cp .env.example .env   # заполнить значения
python -m pg_mcp_qauth.server
```

Docker (ставит зависимости из пиннингового `requirements.lock`;
перегенерация: `pip-compile pyproject.toml -o requirements.lock --strip-extras`):

```bash
docker build -t pg_mcp_qauth .
docker run --env-file .env -p 8000:8000 pg_mcp_qauth
```

## Конфигурация

См. `.env.example`. Ключевые параметры:

- `AUTH_ISSUER`, `JWKS_URI`, `REQUIRED_AUDIENCE`, `ALGORITHMS` — проверка токена.
  `REQUIRED_AUDIENCE` обязателен для защиты от token passthrough.
- `ROLES_CLAIM`, `RLS_USER_CLAIM` — какие claim'ы читать.
- `ROLE_MAP_JSON`, `DEFAULT_ROLE` — маппинг групп в DB-роли.
- `PG_*` — реквизиты БД (`PG_USER` см. требования в runbook).
- `MAX_ROWS`, `STATEMENT_TIMEOUT_MS`, `POOL_*`, `ALLOW_SYSTEM_SCHEMAS`.

## Подключение MCP-клиентов

Сервер публикует RFC 9728 metadata (URL рекламируется в `401`-challenge:
`WWW-Authenticate: Bearer resource_metadata="…"`), поэтому OAuth-совместимые клиенты
сами обнаруживают Authorization Server и открывают браузерный логин.

**VS Code** (`.vscode/mcp.json`) — вход через браузер против realm'а Keycloak:

```json
{
  "servers": {
    "pg_mcp_qauth": {
      "type": "http",
      "url": "http://localhost:8000/mcp",
      "oauth": { "clientId": "pg-mcp" }
    }
  }
}
```

**Claude Code** — то же самое обнаружение, либо статичный токен для скриптов/CI:

```bash
claude mcp add --transport http pgmcp http://localhost:8000/mcp \
  --header "Authorization: Bearer $ACCESS_TOKEN"
```

> **Нюанс DCR:** при динамической регистрации клиентов токен выдаётся для
> *созданного на лету* клиента — без твоих audience/group mapper'ов. Фиксируй клиент
> через `oauth.clientId` (или аналог в твоём AS), чтобы токены сохраняли claim'ы, на
> которые опирается модель доступа.

## Безопасность (SQL Guard)

`run_query` принимает только одиночный `SELECT` (в т.ч. `WITH ... SELECT` и set-операции),
проверяемый разбором в AST (`sqlglot`, диалект postgres):

- отвергаются DML/DDL (`INSERT`/`UPDATE`/`DELETE`/`CREATE`/`ALTER`/`DROP`/`TRUNCATE`/`GRANT`),
  множественные инструкции, `SET`/`COMMIT` и т.п.;
- блокируется denylist опасных функций (`pg_sleep`, `pg_read_file`, `lo_import`, `dblink`,
  `set_config`, `nextval`, advisory-локи `pg_advisory_lock`/`pg_try_advisory_lock`, …);
- системные схемы (`pg_catalog`, `information_schema`) закрыты, если не разрешены явно;
- результат ограничивается `MAX_ROWS` (авто-`LIMIT`);
- **round-trip-целостность**: так как выполняется пересобранная SQL, guard сверяет
  набор операторных токенов до/после ресериализации и явно отвергает запросы,
  которые парсер мог бы молча исказить (например оператор ParadeDB `@@@`,
  который sqlglot превращает в `@@ $'..'`). Обычный `@@ to_tsquery(...)` работает.

Конфигурация авторизации жёстко валидируется на старте (`Settings.check()`):
`REQUIRED_AUDIENCE` обязателен (иначе не проверяется claim `aud` — token passthrough),
`ALGORITHMS` — ровно один асимметричный алгоритм (HS*/`none` отвергаются).
`MCP_BASE_URL` участвует в RFC 9728-метаданных ресурса; за реверс-прокси укажите
внешний URL. `/health` выполняет реальный `SELECT 1` в Postgres (503 при недоступной БД).

### Защита в глубине (рекомендуется в runbook)

Denylist функций неполон по природе, поэтому основные гарантии даёт сам Postgres:
`PG_USER` не superuser и не владелец таблиц, транзакция `READ ONLY`, роль без `CREATE`.
Дополнительно отзовите выполнение опасных функций у `PUBLIC` и целевых ролей:

```sql
REVOKE EXECUTE ON FUNCTION
    pg_sleep(float8), pg_sleep_for(interval), pg_sleep_until(timestamptz),
    pg_read_file(text), pg_ls_dir(text), lo_import(text), lo_export(oid, text)
FROM PUBLIC;
```

## Инструменты MCP

- `list_tables()` — таблицы/вьюхи, доступные текущей роли.
- `describe_table(table_name)` — колонки, типы, nullability, комментарии (чтением из каталога).
- `run_query(sql)` — безопасный read-only запрос.

### Dry-run превью прав (без сервера)

`pg-mcp-preview` показывает, во что токен превратится на стороне доступа: совпавшую
группу, DB-роль, источник маппинга и (с `--check-db`) реальный список видимых таблиц
под этой ролью. Подпись JWT не проверяется — это отладка `ROLE_MAP_JSON`, а не auth:

```bash
echo "$ACCESS_TOKEN" | pg-mcp-preview -            # только маппинг
echo "$ACCESS_TOKEN" | pg-mcp-preview - --check-db # + список таблиц из БД
```

## Тесты

Unit-тесты SQL-guard (без БД):

```bash
pytest
```

Интеграционный end-to-end прогон (реальный Postgres + локально подписанные JWT +
локальный JWKS + живой MCP-клиент по Streamable HTTP):

```bash
docker run -d --name pgmcp_test -e POSTGRES_DB=analytics \
  -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -p 55432:5432 \
  -v "$PWD/integration/init.sql:/docker-entrypoint-initdb.d/init.sql:ro" postgres:16-alpine
IT_PG_PORT=55432 python integration/run_integration.py
docker rm -f pgmcp_test
```

Проверяются: JWT-авторизация (iss/aud/подпись через JWKS), маппинг group→роль и
`SET LOCAL ROLE` (изоляция схемы/таблиц через GRANT), построчный RLS (одна роль, разные
пользователи → разные строки), отказ DML и системных схем, чтение из каталога.
Для продакшена достаточно заменить `AUTH_ISSUER`/`JWKS_URI` на реальные значения
Keycloak/Authentik — код не меняется.

Боевой прогон против **настоящего Keycloak** (реальный OAuth token endpoint, JWKS, группы,
audience-mapper) — см. `integration/run_keycloak.py` и `CONTRIBUTING.md`.

### Данные для ручных тестов: DVD Rental + pg_search

Интеграционный фикстур `integration/init.sql` — синтетический (4 строки), поэтому для
проверок джойнов, агрегатов и полнотекстового поиска удобнее поднять реальный датасет.
Никакой auth-обвязки (Keycloak, роли, RLS) здесь не нужно — только Postgres с данными.

```bash
curl -sL -o /tmp/dvdrental.tar \
  https://raw.githubusercontent.com/ferry8/dvdrental.tar/master/dvdrental.tar   # ~2.8 MB, pg_dump -F c

docker run -d --name pgmcp_sample -e POSTGRES_DB=analytics \
  -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -p 55432:5432 \
  paradedb/paradedb:0.25.10-pg17

docker exec -i pgmcp_sample pg_restore -U postgres -d analytics --no-owner < /tmp/dvdrental.tar
docker rm -f pgmcp_sample   # удалить (данные в анонимном volume)
```

Подключение: `localhost:55432`, БД `analytics`, `postgres`/`postgres`. В образе уже доступен
`pg_search` (BM25/Tantivy, расширение установлено по умолчанию):

```sql
CREATE INDEX film_bm25 ON film USING bm25 (film_id, title, description)
WITH (key_field='film_id',
      text_fields='{"title":{"tokenizer":{"type":"icu"}},"description":{"tokenizer":{"type":"icu"}}}');

-- Поиск по индексу + JOIN с обычным фильтром (1000 фильмов, 16k прокатов):
SELECT f.film_id, f.title, c.name AS category, paradedb.score(f.film_id) AS score
FROM film f
JOIN film_category fc USING (film_id)
JOIN category c USING (category_id)
WHERE f @@@ 'description:documentary'
  AND f.release_year = 2006
ORDER BY score DESC
LIMIT 10;
```

`ORDER BY paradedb.score(...)` оставляем «голым» (без `round()` и прочего) — иначе
планировщик уходит с TopK-скана и предупреждает о деградации.

> **Ограничение через `run_query`:** оператор `@@@` не переживает ресериализацию
> sqlglot и явно отвергается guard-ом. В MCP-запросах используйте стандартный
> FTS `@@` (например `fulltext @@ to_tsquery('english','amazing')`); `@@@` и BM25
> остаются доступны при работе с БД напрямую (psql).

## Установка как пакета

```bash
pip install .            # или: pip install -e ".[dev]" для разработки
pg-mcp-qauth             # console-script (эквивалент python -m pg_mcp_qauth.server)
```

## Примечания

- Проверено на **FastMCP 4.x** (`RemoteAuthProvider` + `JWTVerifier` из
  `fastmcp.server.auth.providers.jwt`, `fastmcp.server.dependencies.get_access_token`,
  транспорт `http`). Важно: сам `JWTVerifier` не публикует маршруты RFC 9728 — metadata
  отдаёт только обёртка `RemoteAuthProvider`.
- Dynamic Client Registration (RFC 7591) в свежей спецификации MCP deprecated — не является
  основным механизмом онбординга.

## Безопасность

Сообщения об уязвимостях — **не** через публичные issue. См. [SECURITY.md](SECURITY.md).

## Contributing

См. [CONTRIBUTING.md](CONTRIBUTING.md) — настройка, запуск тестов (unit / интеграционные /
боевые с Keycloak), требования к PR.

## Лицензия

[MIT](LICENSE) © 2026 martystev
