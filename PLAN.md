# План реализации: Postgres MCP Server с OAuth-авторизацией (pg_mcp_qauth)

Защищённый MCP-сервер (Model Context Protocol) для чтения из PostgreSQL, интегрированный
с OAuth 2.1 по модели, которую требует Claude Code: сервер выступает **Resource Server**,
а выдачу токенов обеспечивает внешний **Authorization Server** (Keycloak/Authentik).

## Архитектура и роли OAuth

По спецификации MCP (2026) роли разделены жёстко:

- **Claude Code = OAuth 2.1 client** — проходит OAuth-флоу (PKCE) с Authorization Server, получает access-токен.
- **pg_mcp_qauth = OAuth 2.1 resource server** — валидирует токен, отдаёт `401` + `WWW-Authenticate`
  со ссылкой на OAuth Protected Resource Metadata (RFC 9728), рекламируя свой AS.
- **Keycloak/Authentik = Authorization Server (единый брокер)** — выдаёт токены и обеспечивает
  мультипровайдерность через identity brokering.

```
                     +-------------------+
                     |   Claude Code     |  (OAuth 2.1 client)
                     +---------+---------+
                               |
            (a) OAuth flow PKCE| получить токен
                               v
                  +---------------------------+
                  | Keycloak / Authentik (AS) |  единый брокер
                  |  identity brokering ->    |
                  |  Google / Entra ID / AD / |
                  |  Okta / GitHub / ...      |
                  +-------------+-------------+
                                | issued JWT
       1. Bearer JWT            v
                  +---------------------------+
                  |  pg_mcp_qauth (RS, FastMCP)|
                  |  - Streamable HTTP         |
                  |  - RFC 9728 metadata       |
                  |  - JWKS verify (1 issuer)  |
                  +-------------+-------------+
                                |
   2. JWT claims -> DB role     | 3. SET LOCAL ROLE + set_config(GUC)
                                v
                  +---------------------------+
                  | PostgreSQL                |
                  |  - SET TRANSACTION READ ONLY
                  |  - SET LOCAL ROLE <role>  |
                  |  - RLS by session GUC     |
                  +---------------------------+
```

### Мультипровайдерность (вариант A — федерация через один AS)

Claude Code в discovery-потоке указывает на **один** Authorization Server, поэтому
мультипровайдерность обеспечивается **не кодом MCP**, а брокером на стороне AS:

- Пользователь логинится через любого внешнего провайдера (Google, Microsoft Entra ID,
  on-prem Active Directory через LDAP/Kerberos/ADFS, Okta, GitHub и т.д.).
- Токен клиенту всегда выдаёт Keycloak/Authentik; MCP валидирует токены **одного issuer** (один JWKS).
- Добавление нового провайдера = настройка коннектора в Keycloak, код MCP не меняется.

> Примечание: Dynamic Client Registration (RFC 7591) в свежей спецификации MCP помечен как
> deprecated — не закладываемся на DCR как основной механизм онбординга клиента.

### Ключевые принципы

1. **Строгая аутентификация**: проверка подписи JWT через JWKS, а также `iss`, `aud`, `exp`, `nbf`
   и `typ`/`token_use = access` (ID-токены не принимаются). Обязательная проверка **audience**,
   чтобы токены других сервисов не проходили (защита от token passthrough).
2. **Изоляция прав на уровне Postgres**: запросы выполняются в транзакции
   `SET TRANSACTION READ ONLY` + `SET LOCAL ROLE <role>`, построчно — через RLS.
3. **Безопасность пула соединений**: `SET LOCAL ROLE` и `set_config(..., true)` действуют только
   в рамках транзакции и не «протекают» на соединение `asyncpg` после её завершения.
4. **SQL Guard на AST**: разрешены только одиночные `SELECT` / `WITH ... SELECT`; DML/DDL,
   сомнительные системные функции и батчи из нескольких инструкций запрещены.
5. **Источник истины о правах = каталоги Postgres** (`GRANT` + RLS) и членство в группах Keycloak,
   а не код MCP.

---

## Модель контроля доступа (три уровня)

Права крепятся на уровне **ролей/групп**, а не отдельных пользователей: ролей мало, юзеров много.
Пользователь → группа в Keycloak → группа → DB-роль.

| Уровень | Механизм Postgres | Источник |
|---|---|---|
| **Схема** | `GRANT USAGE ON SCHEMA` | DBA-runbook |
| **Таблица** | `GRANT SELECT` на таблицы/вьюхи | DBA-runbook |
| **Строки** | **RLS-политики** по session-GUC | DBA-runbook |

- **Роль (схема/таблица):** JWT-claim `groups`/`roles` маппится в одну DB-роль; MCP делает
  `SET LOCAL ROLE <role>`, Postgres обрезает доступ по грантам.
- **Строки (RLS):** если нужна построчная фильтрация под конкретного юзера, статические вьюхи не
  масштабируются — используется RLS с session-переменной, которую MCP ставит через
  `set_config('app.user_email', <из JWT>, true)` (и/или `app.groups`). Одна таблица — разные
  строки для разных юзеров.
- **Вьюхи (опционально):** базовые таблицы можно прикрыть вьюхами и выдавать `SELECT` только на них
  (`REVOKE` с базовых таблиц), чтобы скрыть структуру.

### Provisioning (требования к окружению БД)

- Базовый `PG_USER` пула — **не superuser и не владелец таблиц** (иначе RLS не применяется).
- `PG_USER` является **членом всех целевых ролей**: `GRANT <role> TO pg_user`, иначе `SET ROLE` упадёт.
- При необходимости `ALTER TABLE ... FORCE ROW LEVEL SECURITY`.
- Админ-панель грантов на v1 **не строим** (YAGNI). Если позже понадобится UI — это тонкая обёртка
  поверх каталогов Postgres + групп Keycloak, без своей логики авторизации в MCP.

---

## Структура проекта

```
pg_mcp_qauth/
├── .env.example              # Пример конфигурации окружения
├── Dockerfile                # Сборка контейнера сервиса
├── requirements.txt          # fastmcp, asyncpg, httpx, pydantic, sqlglot (или pglast)
├── README.md                 # Документация, DBA-runbook по грантам/RLS
├── PLAN.md                   # Данный документ
└── pg_mcp_qauth/             # Модуль сервера
    ├── __init__.py
    ├── config.py             # Загрузка и валидация конфигурации env
    ├── auth.py               # Валидация JWT (JWKS) + RemoteAuthProvider (RFC 9728)
    ├── db.py                 # Пул asyncpg, маппинг claims->role, SET LOCAL ROLE + set_config
    ├── sql_guard.py          # AST-валидация SELECT (sqlglot/pglast), авто-LIMIT
    ├── tools.py              # Инструменты FastMCP (list_tables, describe_table, run_query)
    └── server.py             # Точка входа, запуск FastMCP (Streamable HTTP)
```

---

## Детали компонентов

### 1. `config.py`
Настройки из переменных окружения:
- `MCP_BASE_URL`, `MCP_PATH` (публичный URL для метаданных OAuth), транспорт = Streamable HTTP.
- `AUTH_ISSUER` (Keycloak/Authentik), `JWKS_URI`, `REQUIRED_AUDIENCE`, `REQUIRED_SCOPE`.
- `ROLES_CLAIM` (какой claim читать, напр. `groups`), `RLS_USER_CLAIM` (напр. `email`/`sub`).
- Реквизиты БД (`PG_HOST`, `PG_PORT`, `PG_DATABASE`, `PG_USER`, `PG_PASSWORD`).
- Лимиты (`MAX_ROWS`, `STATEMENT_TIMEOUT`, `GRANT_CACHE_TTL`).
- Валидация обязательных полей через `config.check()`.

### 2. `auth.py`
`RemoteAuthProvider` + JWKS-верификация:
- Проверка подписи, `iss`, `aud` (обязательно), `exp`, `nbf`, `typ`/`token_use = access`.
- Отдача `/.well-known/oauth-protected-resource/...` (RFC 9728) и `401` + `WWW-Authenticate`
  для неавторизованных клиентов.

### 3. `db.py`
Пул `asyncpg` и применение прав:
- `resolve_role(claims)` — маппинг claim-группы → DB-роль (с кэшем до `GRANT_CACHE_TTL`, напр. 60 c).
- Выполнение запроса в транзакции:
  ```sql
  BEGIN;
  SET TRANSACTION READ ONLY;
  SET LOCAL ROLE "user_role";
  SELECT set_config('app.user_email', $1, true);   -- для RLS
  SELECT set_config('app.groups',     $2, true);   -- для RLS (опц.)
  SET LOCAL statement_timeout = '30s';
  -- одиночный SELECT ...
  COMMIT;
  ```
- `SET LOCAL` / `set_config(..., true)` гарантируют отсутствие утечки состояния на соединение пула.

### 4. `sql_guard.py`
AST-валидация (не регулярки — они обходимы), через `sqlglot` или `pglast`/`libpg_query`:
- Ровно одна инструкция; только `SELECT` / `WITH ... SELECT`.
- Запрет DML/DDL, системных схем/функций без явного разрешения.
- Безопасный авто-`LIMIT`: оборачивание `SELECT * FROM (<query>) AS _sub LIMIT n`
  (не строковая подстановка, чтобы не ломать `ORDER BY`/существующий `LIMIT`/CTE/`;`).

### 5. `tools.py`
Инструменты FastMCP (все выполняются уже после `SET LOCAL ROLE`):
- `list_tables()` — таблицы, видимые текущей роли; фильтр через `has_table_privilege(...)`.
- `describe_table(table_name)` — структура и комментарии колонок **чтением из каталога**
  (`information_schema` / `pg_description`, `col_description()`, `obj_description()`),
  а не через `COMMENT ON` (это DDL и в read-only не выполнится).
- `run_query(sql)` — безопасный запуск чтения через `sql_guard` + транзакцию.

---

## План проверки (Verification)

1. **Автоматические тесты**:
   - Unit-тесты `sql_guard`: инъекции, многостатейные запросы, DML/DDL, системные функции,
     корректность авто-`LIMIT` (adversarial-набор на обход AST-guard).
   - Тесты `resolve_role` / маппинга claims.
   - Тесты валидации конфигурации (`config.check()`).

2. **Интеграционные тесты**:
   - Реальный Keycloak/Authentik + Postgres: полный OAuth-флоу через MCP-клиента.
   - Проверка RLS: разные юзеры в одной роли видят разные строки.
   - Проверка `SET LOCAL ROLE`: гранты по схеме/таблицам реально обрезают доступ.

3. **Ручная проверка**:
   - Запуск сервера локально / в Docker.
   - `curl` на `/.well-known/oauth-protected-resource` и `/mcp`.
   - Поведение при некорректном/отсутствующем Bearer-токене (401 + `WWW-Authenticate`).
   - Токен с чужим `aud` отклоняется.
