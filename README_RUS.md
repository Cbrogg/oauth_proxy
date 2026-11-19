# litellm-oauth-facade

> [English version](README.md)

Узкий **OAuth-фасад** перед **LiteLLM** (по умолчанию) и любым другим **Streamable HTTP MCP endpoint** для подключения ChatGPT Apps к MCP toolsets.

ChatGPT требует OAuth **Resource Server** (metadata + Bearer-токен от Authorization Server). Апстрим MCP-сервер (LiteLLM или любой другой endpoint) использует свою авторизацию — Virtual Key в заголовке для LiteLLM, либо API-ключ / токен вызывающего для обычного endpoint. Фасад закрывает этот разрыв:

1. Отдаёт OAuth metadata (discovery, protected-resource) для ChatGPT.
2. Валидирует JWT от Authorization Server и определяет пользователя через `userinfo`.
3. Пропускает **только** whitelist-пользователей из конфига (`users`); остальным — `403`, запрос до апстрима не доходит.
4. Снимает токен вызывающего, подставляет **персональные** заголовки (Virtual Key для LiteLLM, или API-ключ для обычного endpoint) и проксирует на апстрим. При `forward_access_token` — передаёт проверенный токен как есть.

Это **не** универсальный OAuth/MCP proxy: фасад **не** является Authorization Server, MCP-сервером, tool registry и не выпускает JWT. Он валидирует OAuth (Pocket ID) и проксирует на Streamable HTTP MCP endpoint, на который указывает каждый toolset — по умолчанию LiteLLM, или любой другой сервер.

```
ChatGPT
  → OAuth metadata на фасаде (RS)
  → login/token на домене Pocket ID
  → MCP запросы на фасад с access token от Pocket ID
       ↓ крипто-валидация JWT → aud (client_id) → lookup по sub
       ↓ sub не в users → 403 (стоп, апстрим не трогаем)
       ↓ есть → strip Authorization → inject заголовки пользователя
       ↓ (или forward_access_token → пропускаем токен как есть)
  → апстрим MCP endpoint (LiteLLM / или свой base_url, напр. /api/mcp)
       ↓
  → Memos / N8N / Kryton / … (настраивается на этом MCP-сервере)
```

## Роли

| Роль | Кто | Зона ответственности |
| --- | --- | --- |
| OAuth AS | Pocket ID | authorize, token, userinfo, JWKS |
| OAuth RS + proxy | **litellm-oauth-facade** | metadata, JWT, ACL, headers → апстрим |
| MCP gateway | **LiteLLM** (по умолчанию) или любой Streamable HTTP MCP сервер | toolsets, MCP servers, tools, keys |
| MCP client | ChatGPT | OAuth + Streamable HTTP |

## Топология деплоя

В репозитории готовый продовый стек `docker compose`:

| Сервис | Образ | Назначение |
| --- | --- | --- |
| `traefik` | `traefik:v3.1` | Edge, TLS (Let's Encrypt), маршрутизация по host через Docker labels |
| `facade` | `ghcr.io/cbrogg/oauth_proxy:latest` | OAuth RS + proxy |
| `pocketid` | `ghcr.io/stonith404/pocket-id:latest` | OAuth Authorization Server |
| `litellm` | `ghcr.io/berriai/litellm-database:main-latest` | MCP gateway / toolsets |
| `postgres` | `postgres:17-alpine` | база данных LiteLLM |

Все публичные сервисы торчатся через Traefik на разных hostname. Фасад ходит в LiteLLM по **внутренней** compose-сети (`http://litellm:4000`), а OAuth-эндпоинты указывают на **публичный** hostname Pocket ID — чтобы `iss`/`aud` JWT были консистентны.

## Требования

- Go 1.26+ (локальный режим) **или** Docker / Docker Compose (стек).
- Публичные DNS-записи `A`/`CNAME` на хост для трёх доменов (нужно для Let's Encrypt).
- Порты `80` и `443` доступны из интернета.

## Быстрый старт (Docker Compose, прод)

### 1. Подготовка

- Docker-хост (CE) с `docker compose` v2 и `git`.
- Три публичных домена, которыми вы владеете:
  - фасад, напр. `mcp-auth.example.com`
  - Pocket ID, напр. `id.example.com`
  - LiteLLM, напр. `litellm.example.com`
- DNS `A` (или `CNAME`) на хост для всех трёх доменов и внешний доступ к портам `80`/`443`.

Склонируйте репозиторий и создайте окружение:

```sh
git clone <your-repo-url> && cd oauth_proxy
cp .env.example .env
# создать хранилище ACME-сертификатов (должно существовать и быть доступно на запись до старта Traefik)
touch deploy/acme.json && chmod 600 deploy/acme.json
```

### 2. Заполните `.env`

Откройте `.env` и заполните каждое значение:

- **Домены**: `DOMAIN_FACADE`, `DOMAIN_POCKETID`, `DOMAIN_LITELLM` — три публичных hostname.
- **TLS**: `ACME_EMAIL` — контактный адрес для Let's Encrypt.
- **PostgreSQL**: `POSTGRES_USER`, `POSTGRES_PASSWORD` (надёжный), `POSTGRES_DB`.
- **LiteLLM**: `LITELLM_MASTER_KEY` (для входа в админку/API LiteLLM) и `LITELLM_SALT_KEY` (для хеширования ключей; **должен быть стабильным** — после его смены база становится нечитаемой).
- **Pocket ID client**: `CHATGPT_POCKET_ID_CLIENT_ID` — из шага 5.
- **Пользователь фасада**: `POCKET_ID_USER_SUB` — из шага 5; `LITELLM_KEY_USER1_MEMOS` / `LITELLM_KEY_USER1_N8N` — из шага 4.

### 3. Первый запуск

Запустите сервисы, нужные для настройки (заглушки для ещё неизвестных значений — ок, их читает фасад, который перезапустим позже):

```sh
docker compose up -d
docker compose ps
```

Traefik получит сертификаты для доменов (может занять ~1–2 мин). Если нужно, следите за логами:

```sh
docker compose logs -f traefik
```

### 4. Настройте LiteLLM (toolsets + ключи)

Откройте `https://<DOMAIN_LITELLM>` и войдите по `LITELLM_MASTER_KEY`:

- Создайте MCP **toolset** под каждый бэкенд (например `memos`, `n8n`).
- Создайте **Virtual Key** на каждого пользователя и toolset (например `user1-memos`, `user1-n8n`).

Сгенерированные ключи пропишите в `.env`:
`LITELLM_KEY_USER1_MEMOS`, `LITELLM_KEY_USER1_N8N`.

### 5. Настройте Pocket ID (AS + OIDC-клиент)

Откройте `https://<DOMAIN_POCKETID>`. При **первом** визите Pocket ID запросит создать аккаунт администратора — создайте и пройдите онбординг.

Далее:

- Откройте **пользователя**, под которым работает ChatGPT-человек, и скопируйте его **User ID** (это `sub`) → `POCKET_ID_USER_SUB`.
- Создайте **OIDC-приложение** для ChatGPT с `Redirect URI = https://<DOMAIN_FACADE>` (пустой additional URI — ок). Скопируйте сгенерированный **Client ID** → `CHATGPT_POCKET_ID_CLIENT_ID`.

### 6. Перезапустите фасад с реальными значениями

```sh
docker compose up -d facade
```

Если фасад упал при старте (ему нужен доступный Pocket ID на этапе загрузки) — compose перезапустит его автоматически (`restart: unless-stopped`).

### 7. Проверка

Эндпоинты и флоу для проверки:

```sh
# readiness
curl -s https://<DOMAIN_FACADE>/healthz
curl -s https://<DOMAIN_FACADE>/readyz
# OAuth protected-resource metadata (ChatGPT обнаруживает MCP по нему)
curl -fsS https://<DOMAIN_FACADE>/.well-known/oauth-protected-resource/toolset/memos/mcp
```

Smoke-тесты (задайте `FACADE_URL`/`LITELLM_URL`, экспортируйте реальный Pocket ID `ACCESS_TOKEN`):

```sh
FACADE_URL=https://<DOMAIN_FACADE> \
LITELLM_URL=https://<DOMAIN_LITELLM> \
ACCESS_TOKEN=<pocket-id-access-token> \
  bash scripts/smoke.sh
```

### 8. Подключение ChatGPT

В ChatGPT Apps задайте OAuth-флоу на фасад:

- **OAuth client ID** = `CHATGPT_POCKET_ID_CLIENT_ID` (пользователь авторизуется на домене Pocket ID).
- **MCP server URL** = `https://<DOMAIN_FACADE>/toolset/<NAME>/mcp` для каждого toolset.

Пользователь логинится на Pocket ID; ChatGPT получает access token и вызывает фасад, который валидирует его и проксирует на LiteLLM.

## Локальный / одиночный режим (разработка)

Pocket ID/LiteLLM в репозитории не нужны, чтобы собрать только фасад:

```sh
go build -o facade ./cmd/facade
./facade -config config.yaml
```

Или на Docker, только фасад:

```sh
docker run --rm -p 8080:8080 \
  -v "$PWD/config.yaml:/config/config.yaml:ro" \
  -e LITELLM_KEY_USER1_MEMOS=... \
  -e LITELLM_KEY_USER1_N8N=... \
  ghcr.io/cbrogg/oauth_proxy:latest
```

Сборка выполняется из `cmd/facade`, бинарник называется `facade`, слушает порт `8080`. По умолчанию путь к конфигу — `/config/config.yaml` (флаг `-config`).

## Конфигурация

Пример — в [`config.example.yaml`](config.example.yaml). Конфиг загружается из YAML, значения вида `${ENV_VAR}` подставляются из окружения. В стеке это файл `deploy/facade-config.yaml`, смонтированный в `/config/config.yaml` внутри контейнера.

```yaml
server:
  listen: ":8080"
  public_url: "https://YOUR-PUBLIC-FACADE-DOMAIN"   # обязателен
  log_level: "info"
  cors:
    allowed_origins: ["https://app.example.com"]    # пусто = любой Origin
    allowed_methods: ["GET", "POST", "DELETE", "OPTIONS"]
    allowed_headers: ["Authorization", "Content-Type"]
    allow_credentials: false
    max_age: "1h"

litellm:
  base_url: "https://YOUR-LITELLM-DOMAIN"
  timeout: "60s"
  shared_key_allowed: false      # true только для dev-прототипа

pocket_id:
  issuer: "https://YOUR-POCKET-ID-ISSUER"
  discovery_url: "https://YOUR-POCKET-ID-ISSUER/.well-known/openid-configuration"
  discovery_cache_ttl: "5m"
  jwks_uri: "https://YOUR-POCKET-ID-ISSUER/.well-known/jwks.json"
  jwks_cache_ttl: "1h"
  userinfo_endpoint: "https://YOUR-POCKET-ID-ISSUER/api/oidc/userinfo"
  userinfo_cache_ttl: "5m"
  token_validation:
    accepted_client_ids: ["${CHATGPT_POCKET_ID_CLIENT_ID}"]
    require_token_type: "oauth-access-token"
    clock_skew: "1m"

identity:
  match_by: "sub"

# Ключ — email (метка). Lookup по полю sub (= Pocket ID user id).
toolsets:
  # LiteLLM toolset: апстрим = litellm.base_url, путь фасада сохраняется.
  memos: {}
  n8n: {}
  # Обычный Streamable HTTP MCP endpoint (не LiteLLM). Путь фасада
  # /toolset/kryton/mcp накладывается на https://kryton.example.com/api/mcp.
  # forward_access_token: передать проверенный токен апстриму вместо заголовков.
  kryton:
    base_url: "https://kryton.example.com/api/mcp"
    timeout: "60s"
    forward_access_token: false

users:
  user@example.com:
    sub: "${POCKET_ID_USER_SUB}"
    toolsets:
      memos:
        headers:
          x-litellm-api-key: "Bearer ${LITELLM_KEY_USER1_MEMOS}"
      n8n:
        headers:
          x-litellm-api-key: "Bearer ${LITELLM_KEY_USER1_N8N}"
      kryton:
        headers:
          x-api-key: "${KRYTON_API_KEY_USER1}"
```

> В compose-деплое `litellm.base_url` — **внутренний** `http://litellm:4000`; `pocket_id.*` указывают на **публичный** hostname Pocket ID. Пример выше — общий (локальный) вид.

### Обязательные поля

- `server.public_url` — публичный адрес фасада (используется в metadata и `WWW-Authenticate`).
- `litellm.base_url` — **дефолтный** апстрим (scheme + host). Пер-таулсетный `base_url` переопределяет его.
- `pocket_id.issuer` и `pocket_id.token_validation.accepted_client_ids`.
- `toolsets` и `users` не должны быть пустыми.

`litellm.base_url` — только scheme+host, без path. В пер-таулсетном `toolsets.<name>.base_url` допустим префикс пути, который накладывается на апстрим MCP endpoint. Обязательного заголовка больше нет: грант может быть без состояния (например, у toolset включён `forward_access_token`) или указывать на публичный endpoint.

### Расшифровка полей пользователя

- Ключ карты — email (метка) пользователя.
- `sub` — идентификатор пользователя в Pocket ID, по нему идёт lookup.
- `toolsets.<name>.headers` — заголовки, которые подставляются в исходящий запрос к апстриму (обычно персональный `x-litellm-api-key` для LiteLLM, или любой заголовок для обычного endpoint).

### Расшифровка апстрима toolset

- `toolsets.<name>.base_url` — опционально. Когда задан, toolset проксируется на этот URL (допустим префикс пути) вместо `litellm.base_url`, а `/toolset/<name>/mcp` накладывается на него. Так подключается **не-LiteLLM** Streamable HTTP MCP сервер, например `https://kryton.example.com/api/mcp`.
- `toolsets.<name>.timeout` — опциональный пер-таулсетный таймаут апстрима (по умолчанию `litellm.timeout`).
- `toolsets.<name>.forward_access_token` — когда `true`, проверенный access token пользователя передаётся апстриму в `Authorization` вместо снятия и подстановки статических заголовков. Выбирайте **одну** стратегию авторизации на toolset.

### CORS

Браузерные MCP-клиенты (ChatGPT Apps, веб-UI) требуют CORS. Фасад обрабатывает и preflight (`OPTIONS`, отвечает `204`), и обычные запросы, добавляя `Vary: Origin`, чтобы прокси кэшировали ответы с учётом origin.

- `server.cors.allowed_origins` — точные разрешённые Origin. **Пустой список разрешает любой Origin** (ответ отражает запрошенный `Origin`). Без wildcard-синтаксиса.
- `server.cors.allowed_methods` / `allowed_headers` — что браузерам разрешено использовать/слать (дефолты соответствуют маршрутам фасада и `Authorization`/`Content-Type`).
- `server.cors.allow_credentials` — отправляет `Access-Control-Allow-Credentials`. Держите `false`, если фасад не за общим доменом с cookie; включает авторизацию неявно и отключает форму `*`.
- `server.cors.max_age` — на сколько браузер может кэшировать preflight (например `1h`).

## URL-маршруты

Для каждого toolset `NAME` экспонируются:

- `/toolset/NAME/mcp` и `/toolset/NAME/mcp/` — метод сервера MCP (POST/GET/DELETE) с OAuth-проверкой.
- `/.well-known/oauth-protected-resource/toolset/NAME/mcp` — protected-resource metadata.
- `/.well-known/openid-configuration/toolset/NAME/mcp` — зеркало discovery Pocket ID.
- `/.well-known/oauth-authorization-server/toolset/NAME/mcp` — зеркало discovery (alias).
- На базовом пути toolset дублируются те же `.well-known` endpoints.

Служебные:

- `/healthz` — liveness.
- `/readyz` — readiness (готов, когда загружены валидные JWKS).
- `/metrics` — Prometheus метрики.

## Поток авторизации

Для защищённого запроса выполняется цепочка проверок:

1. `RequireBearer` — наличие `Authorization: Bearer …`.
2. `JWTValidate` — крипто-валидация RS256-подписи по JWKS, iss, тип токена, срок действия (с leeway).
3. `ClientIDAllowlist` — совпадение `aud` токена с `accepted_client_ids`.
4. `UserinfoResolve` — небелый пользователь → `403`; иначе запрос `userinfo` в AS (с кэшем) и кросс-проверка `sub`/`email`.
5. `UserWhitelist` — наличие гранта на конкретный toolset, подстановка заголовков (или проброс токена при `forward_access_token`).

Исходящий запрос к апстриму очищается от `Authorization`, `Cookie`, `X-Forwarded-Access-Token` и клиентского `x-litellm-api-key`, затем инжектятся заголовки пользователя. При `toolsets.<name>.forward_access_token: true` проверенный `Authorization` сохраняется и пробрасывается как есть.

## Метрики (Prometheus)

Экспонируются на `/metrics` с префиксом `facade_`:

- `facade_http_requests_total{route,method,status}`
- `facade_auth_failures_total{reason}`
- `facade_proxy_duration_seconds{toolset}`
- `facade_userinfo_cache_hits_total` / `facade_userinfo_cache_misses_total`

## Тесты

```sh
go test ./...
```

## Название и структура

- Модуль: `litellm-oauth-facade`.
- Входная точка: `cmd/facade`.
- Пакеты: `config`, `httpserver`, `middleware`, `proxy`, `metadata`, `identity`, `pocketid`, `metrics`, `logging`, `authctx`.
