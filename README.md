# litellm-oauth-facade

> [Русская версия](README_RUS.md)

A narrow **OAuth facade in front of LiteLLM** for connecting ChatGPT Apps to MCP toolsets.

ChatGPT requires an OAuth **Resource Server** (metadata + a Bearer token from the Authorization Server). LiteLLM accepts a Virtual Key in a header. The facade closes this gap:

1. Serves the OAuth metadata (discovery, protected-resource) for ChatGPT.
2. Validates the JWT from the Authorization Server and resolves the user via `userinfo`.
3. Lets **only** whitelisted users from the config (`users`) through; everyone else gets `403`, and the request never reaches LiteLLM.
4. Injects a **per-user** Virtual Key and proxies to LiteLLM on the same path that arrived at the facade (no rewrite).

This is **not** a general-purpose OAuth/MCP proxy: all MCP management (servers, tools, toolsets, keys) happens in LiteLLM. The facade is **not** an Authorization Server, an MCP server, a tool registry, and does not issue JWTs.

```
ChatGPT
  → OAuth metadata on the facade (RS)
  → login/token on the Pocket ID domain
  → MCP requests to the facade with a Pocket ID access token
       ↓ crypto-validate JWT → aud (client_id) → lookup by sub
       ↓ sub not in users → 403 (stop, LiteLLM untouched)
       ↓ present → strip Authorization → inject the user's x-litellm-api-key
  → LiteLLM (same URL path, e.g. /toolset/memos/mcp)
       ↓
  → Memos / Firefly / … (configured in the LiteLLM UI, not in the facade)
```

## Roles

| Role | Who | Area of responsibility |
| --- | --- | --- |
| OAuth AS | Pocket ID | authorize, token, userinfo, JWKS |
| OAuth RS + proxy | **litellm-oauth-facade** | metadata, JWT, ACL, headers → LiteLLM |
| MCP gateway | **LiteLLM** | toolsets, MCP servers, tools, virtual keys |
| MCP client | ChatGPT | OAuth + Streamable HTTP |

## Deployment topology

The repository ships a production-ready `docker compose` stack:

| Service | Image | Purpose |
| --- | --- | --- |
| `traefik` | `traefik:v3.1` | Edge, TLS (Let's Encrypt), routing by host via Docker labels |
| `facade` | `ghcr.io/cbrogg/oauth_proxy:latest` | OAuth RS + proxy |
| `pocketid` | `ghcr.io/stonith404/pocket-id:latest` | OAuth Authorization Server |
| `litellm` | `ghcr.io/berriai/litellm-database:main-latest` | MCP gateway / toolsets |
| `postgres` | `postgres:17-alpine` | LiteLLM database |

All public services are exposed through Traefik on distinct hostnames. The facade talks to LiteLLM over the **internal** compose network (`http://litellm:4000`), while the OAuth endpoints point at the **public** Pocket ID hostname — this keeps the JWT `iss`/`aud` consistent.

## Requirements

- Go 1.26+ (local mode) **or** Docker / Docker Compose (stack).
- Public DNS `A`/`CNAME` records for the three domains → the host (required for Let's Encrypt).
- Ports `80` and `443` reachable from the internet.

## Quick Start (Docker Compose, production)

### 1. Prerequisites

- A Docker host (CE) with `docker compose` v2 and `git`.
- Three public domain names you control:
  - facade, e.g. `mcp-auth.example.com`
  - Pocket ID, e.g. `id.example.com`
  - LiteLLM, e.g. `litellm.example.com`
- DNS `A` (or `CNAME`) records for all three pointing at the host, and external access to ports `80`/`443`.

Clone the repository and create your environment:

```sh
git clone <your-repo-url> && cd oauth_proxy
cp .env.example .env
# create the ACME certificate store (must exist and be writable before Traefik starts)
touch deploy/acme.json && chmod 600 deploy/acme.json
```

### 2. Configure `.env`

Open `.env` and fill every value:

- **Domains**: `DOMAIN_FACADE`, `DOMAIN_POCKETID`, `DOMAIN_LITELLM` — the three public hostnames.
- **TLS**: `ACME_EMAIL` — the Let's Encrypt contact address.
- **PostgreSQL**: `POSTGRES_USER`, `POSTGRES_PASSWORD` (strong), `POSTGRES_DB`.
- **LiteLLM**: `LITELLM_MASTER_KEY` (used to log in to the LiteLLM admin UI / API) and `LITELLM_SALT_KEY` (used to hash keys; **must stay stable** — the DB is unreadable after it changes).
- **Pocket ID client**: `CHATGPT_POCKET_ID_CLIENT_ID` — from step 5.
- **Facade user**: `POCKET_ID_USER_SUB` — from step 5; `LITELLM_KEY_USER1_MEMOS` / `LITELLM_KEY_USER1_N8N` — from step 6.

### 3. First boot

Start services that are needed for setup (mock values for the not-yet-known entries are fine — they are read by the facade, which will restart later):

```sh
docker compose up -d
docker compose ps
```

Traefik pulls certs for the domains (may take up to ~1–2 min). Watch logs if needed:

```sh
docker compose logs -f traefik
```

### 4. Configure LiteLLM (create toolsets + keys)

Open `https://<DOMAIN_LITELLM>` and log in with `LITELLM_MASTER_KEY`:

- Create an MCP **toolset** for each backend (e.g. `memos`, `n8n`).
- Create a **Virtual Key** per user per toolset (e.g. `user1-memos`, `user1-n8n`).

Write the generated keys into `.env`:
`LITELLM_KEY_USER1_MEMOS`, `LITELLM_KEY_USER1_N8N`.

### 5. Configure Pocket ID (AS + OIDC client)

Open `https://<DOMAIN_POCKETID>`. On the **first** visit Pocket ID asks you to create the admin account — do it and finish onboarding.

Then:

- Open the **user** the ChatGPT person uses and copy its **User ID** (this is `sub`) → `POCKET_ID_USER_SUB`.
- Create an **OIDC application** for ChatGPT with `Redirect URI = https://<DOMAIN_FACADE>` (blank additional URI is fine). Copy the generated **Client ID** → `CHATGPT_POCKET_ID_CLIENT_ID`.

### 6. Restart the facade with the real values

```sh
docker compose up -d facade
```

If the facade fails to start (it needs Pocket ID reachable at boot), compose will retry automatically (`restart: unless-stopped`).

### 7. Verify

Endpoints and flows to check:

```sh
# readiness
curl -s https://<DOMAIN_FACADE>/healthz
curl -s https://<DOMAIN_FACADE>/readyz
# OAuth protected-resource metadata (ChatGPT discovers MCP from this)
curl -fsS https://<DOMAIN_FACADE>/.well-known/oauth-protected-resource/toolset/memos/mcp
```

Smoke tests (set `FACADE_URL`/`LITELLM_URL`, export a real Pocket ID `ACCESS_TOKEN`):

```sh
FACADE_URL=https://<DOMAIN_FACADE> \
LITELLM_URL=https://<DOMAIN_LITELLM> \
ACCESS_TOKEN=<pocket-id-access-token> \
  bash scripts/smoke.sh
```

### 8. Connect ChatGPT

In ChatGPT Apps, set the OAuth flow to the facade:

- **OAuth client ID** = `CHATGPT_POCKET_ID_CLIENT_ID` (the user authorizes on the Pocket ID domain).
- **MCP server URL** = `https://<DOMAIN_FACADE>/toolset/<NAME>/mcp` for each toolset.

The user logs in on Pocket ID; ChatGPT obtains an access token and calls the facade, which validates it and proxies to LiteLLM.

## Local / single-container mode (development)

You do not need LiteLLM/Pocket ID in the repo to build just the facade:

```sh
go build -o facade ./cmd/facade
./facade -config config.yaml
```

Or via Docker on the facade alone:

```sh
docker run --rm -p 8080:8080 \
  -v "$PWD/config.yaml:/config/config.yaml:ro" \
  -e LITELLM_KEY_USER1_MEMOS=... \
  -e LITELLM_KEY_USER1_N8N=... \
  ghcr.io/cbrogg/oauth_proxy:latest
```

The build runs from `cmd/facade`, the binary is named `facade`, and it listens on port `8080`. The default config path is `/config/config.yaml` (flag `-config`).

## Configuration

See [`config.example.yaml`](config.example.yaml). The config is loaded from YAML, and values of the form `${ENV_VAR}` are substituted from the environment. In the compose stack this file is `deploy/facade-config.yaml`, mounted at `/config/config.yaml` inside the container.

```yaml
server:
  listen: ":8080"
  public_url: "https://YOUR-PUBLIC-FACADE-DOMAIN"   # required
  log_level: "info"

litellm:
  base_url: "https://YOUR-LITELLM-DOMAIN"
  timeout: "60s"
  shared_key_allowed: false      # true only for a dev prototype

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

# Key = email (label). Lookup is done by the field sub (= Pocket ID user id).
toolsets:
  memos: {}
  n8n: {}

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
```

> In the compose deployment, `litellm.base_url` is the **internal** `http://litellm:4000`; `pocket_id.*` point to the **public** Pocket ID hostname. The example above shows the general (local) form.

### Required fields

- `server.public_url` — the public address of the facade (used in metadata and `WWW-Authenticate`).
- `litellm.base_url` — scheme + host only, no path.
- `pocket_id.issuer` and `pocket_id.token_validation.accepted_client_ids`.
- `toolsets` and `users` must not be empty.
- Each `users.<email>.toolsets.<name>` needs a `headers.x-litellm-api-key`.

### User field breakdown

- The map key is the user's email (label).
- `sub` — the user identifier in Pocket ID; the lookup is done by it.
- `toolsets.<name>.headers` — the headers injected into the outgoing request to LiteLLM (usually a per-user `x-litellm-api-key`).

## URL routes

For each toolset `NAME` the following are exposed:

- `/toolset/NAME/mcp` and `/toolset/NAME/mcp/` — the MCP server method (POST/GET/DELETE) with OAuth checks.
- `/.well-known/oauth-protected-resource/toolset/NAME/mcp` — protected-resource metadata.
- `/.well-known/openid-configuration/toolset/NAME/mcp` — mirror of the Pocket ID discovery.
- `/.well-known/oauth-authorization-server/toolset/NAME/mcp` — mirror of the discovery (alias).
- The same `.well-known` endpoints are also mirrored at the base path of the toolset.

Operational:

- `/healthz` — liveness.
- `/readyz` — readiness (ready once valid JWKS are loaded).
- `/metrics` — Prometheus metrics.

## Authorization flow

For a protected request the following chain of checks runs:

1. `RequireBearer` — `Authorization: Bearer …` is present.
2. `JWTValidate` — crypto-validates the RS256 signature against JWKS, iss, token type, and expiry (with leeway).
3. `ClientIDAllowlist` — the token's `aud` matches `accepted_client_ids`.
4. `UserinfoResolve` — a non-white user → `403`; otherwise a `userinfo` request to the AS (cached) and a cross-check of `sub`/`email`.
5. `UserWhitelist` — a grant for the specific toolset exists, and headers are injected.

The outgoing request to LiteLLM is stripped of `Authorization`, `Cookie`, `X-Forwarded-Access-Token`, and the client's `x-litellm-api-key`, then the user headers are injected.

## Metrics (Prometheus)

Exposed on `/metrics` with the `facade_` prefix:

- `facade_http_requests_total{route,method,status}`
- `facade_auth_failures_total{reason}`
- `facade_proxy_duration_seconds{toolset}`
- `facade_userinfo_cache_hits_total` / `facade_userinfo_cache_misses_total`

## Tests

```sh
go test ./...
```

## Name and structure

- Module: `litellm-oauth-facade`.
- Entry point: `cmd/facade`.
- Packages: `config`, `httpserver`, `middleware`, `proxy`, `metadata`, `identity`, `pocketid`, `metrics`, `logging`, `authctx`.
