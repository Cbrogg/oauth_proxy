#!/usr/bin/env bash
# Smoke-проверки MVP (§10, §15 ТЗ). Требуют запущенный фасад и валидный Pocket ID access token.
set -euo pipefail

FACADE_URL="${FACADE_URL:-https://mcp-auth.example.com}"
LITELLM_URL="${LITELLM_URL:-https://litellm.example.com}"
ACCESS_TOKEN="${ACCESS_TOKEN:-}"

echo "== metadata path A =="
curl -fsS "${FACADE_URL}/.well-known/oauth-protected-resource/toolset/memos/mcp" | head -c 200
echo

echo "== metadata path B =="
curl -fsS "${FACADE_URL}/toolset/memos/mcp/.well-known/oauth-protected-resource" | head -c 200
echo

echo "== MCP without Bearer (expect 401) =="
code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${FACADE_URL}/toolset/memos/mcp" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}')
test "$code" = "401"

echo "== OPTIONS (expect 204) =="
code=$(curl -sS -o /dev/null -w '%{http_code}' -X OPTIONS "${FACADE_URL}/toolset/memos/mcp")
test "$code" = "204"

if [[ -n "${LITELLM_KEY_USER1_MEMOS:-}" ]]; then
  echo "== LiteLLM direct initialize =="
  curl -fsS -X POST "${LITELLM_URL}/toolset/memos/mcp" \
    -H "x-litellm-api-key: Bearer ${LITELLM_KEY_USER1_MEMOS}" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
    | head -c 300
  echo
fi

if [[ -n "$ACCESS_TOKEN" ]]; then
  echo "== Facade with Pocket ID token =="
  curl -fsS -X POST "${FACADE_URL}/toolset/memos/mcp" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
    | head -c 300
  echo
else
  echo "SKIP facade auth test: set ACCESS_TOKEN to a Pocket ID access token"
fi

echo "smoke OK"
