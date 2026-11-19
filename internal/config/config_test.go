package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadAndValidate(t *testing.T) {
	t.Setenv("CHATGPT_POCKET_ID_CLIENT_ID", "f3df1491-e6cd-411f-8b74-4219f2953536")
	t.Setenv("LITELLM_KEY_USER1_MEMOS", "sk-test-user1-memos")
	t.Setenv("POCKET_ID_USER_SUB", "YOUR-POCKET-ID-USER-SUB")

	cfg, err := Load(filepath.Join("..", "..", "config.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	if cfg.ToolsetBasePath("memos") != "/toolset/memos/mcp" {
		t.Fatalf("base path: %s", cfg.ToolsetBasePath("memos"))
	}
	if cfg.ResourceURI("memos") != "https://YOUR-PUBLIC-FACADE-DOMAIN/toolset/memos/mcp" {
		t.Fatalf("resource uri: %s", cfg.ResourceURI("memos"))
	}

	user, ok := cfg.Index.Lookup("YOUR-POCKET-ID-USER-SUB")
	if !ok {
		t.Fatal("expected user in index")
	}
	if user.Email != "user@example.com" {
		t.Fatalf("email: %s", user.Email)
	}
	headers, ok := user.Grant("memos")
	if !ok || headers["x-litellm-api-key"] != "Bearer sk-test-user1-memos" {
		t.Fatalf("grant headers: %v", headers)
	}
}

func TestDuplicateSubRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
server:
  public_url: "https://example.com"
litellm:
  base_url: "https://litellm.example.com"
pocket_id:
  issuer: "https://id.example.com"
  discovery_url: "https://id.example.com/.well-known/openid-configuration"
  jwks_uri: "https://id.example.com/.well-known/jwks.json"
  userinfo_endpoint: "https://id.example.com/userinfo"
  token_validation:
    accepted_client_ids: ["client-1"]
toolsets:
  memos: {}
users:
  a@example.com:
    sub: "same-sub"
    toolsets:
      memos:
        headers:
          x-litellm-api-key: "Bearer key-a"
  b@example.com:
    sub: "same-sub"
    toolsets:
      memos:
        headers:
          x-litellm-api-key: "Bearer key-b"
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected duplicate sub error")
	}
}

func TestDuplicateKeyAllowed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
server:
  public_url: "https://example.com"
litellm:
  base_url: "https://litellm.example.com"
pocket_id:
  issuer: "https://id.example.com"
  discovery_url: "https://id.example.com/.well-known/openid-configuration"
  jwks_uri: "https://id.example.com/.well-known/jwks.json"
  userinfo_endpoint: "https://id.example.com/userinfo"
  token_validation:
    accepted_client_ids: ["client-1"]
toolsets:
  memos: {}
  n8n: {}
users:
  a@example.com:
    sub: "sub-a"
    toolsets:
      memos:
        headers:
          x-litellm-api-key: "Bearer same-key"
      n8n:
        headers:
          x-litellm-api-key: "Bearer same-key"
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("expected duplicate key to be allowed: %v", err)
	}
}

func TestToolsetUpstreamResolution(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
server:
  public_url: "https://example.com"
litellm:
  base_url: "https://litellm.example.com"
  timeout: "30s"
pocket_id:
  issuer: "https://id.example.com"
  discovery_url: "https://id.example.com/.well-known/openid-configuration"
  jwks_uri: "https://id.example.com/.well-known/jwks.json"
  userinfo_endpoint: "https://id.example.com/userinfo"
  token_validation:
    accepted_client_ids: ["client-1"]
toolsets:
  memos: {}
  kryton:
    base_url: "https://kryton.example.com/api/mcp"
    timeout: "60s"
    forward_access_token: true
users:
  a@example.com:
    sub: "sub-a"
    toolsets:
      memos:
        headers:
          x-litellm-api-key: "Bearer key-a"
      kryton: {}
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	litellmRt := cfg.ToolsetUpstream("memos")
	if litellmRt.BaseURL != "https://litellm.example.com" {
		t.Fatalf("litellm base url: %s", litellmRt.BaseURL)
	}
	if litellmRt.Timeout != 30*time.Second {
		t.Fatalf("litellm timeout: %s", litellmRt.Timeout)
	}
	if litellmRt.CustomPath {
		t.Fatal("expected preserved path for LiteLLM toolset")
	}

	krytonRt := cfg.ToolsetUpstream("kryton")
	if krytonRt.BaseURL != "https://kryton.example.com/api/mcp" {
		t.Fatalf("kryton base url: %s", krytonRt.BaseURL)
	}
	if krytonRt.Timeout != time.Minute {
		t.Fatalf("kryton timeout: %s", krytonRt.Timeout)
	}
	if !krytonRt.CustomPath {
		t.Fatal("expected custom path mapping for kryton")
	}
	if !krytonRt.ForwardAccessToken {
		t.Fatal("expected forward_access_token")
	}
}

func TestCORSDefaultsApplied(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
server:
  public_url: "https://example.com"
litellm:
  base_url: "https://litellm.example.com"
pocket_id:
  issuer: "https://id.example.com"
  discovery_url: "https://id.example.com/.well-known/openid-configuration"
  jwks_uri: "https://id.example.com/.well-known/jwks.json"
  userinfo_endpoint: "https://id.example.com/userinfo"
  token_validation:
    accepted_client_ids: ["client-1"]
toolsets:
  memos: {}
users:
  a@example.com:
    sub: "sub-a"
    toolsets:
      memos:
        headers:
          x-litellm-api-key: "Bearer key-a"
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.AllowedOriginsActive() {
		t.Fatal("expected reflect-all default (no explicit list)")
	}
	if cfg.OriginAllowed("https://allowed.example.com") != "https://allowed.example.com" {
		t.Fatal("expected origin to be reflected when no list configured")
	}
	if got := cfg.AllowedMethodsHeader(); got != "GET, POST, DELETE, OPTIONS" {
		t.Fatalf("allowed methods header = %q", got)
	}
	if got := cfg.AllowedHeadersHeader(); got != "Authorization, Content-Type" {
		t.Fatalf("allowed headers header = %q", got)
	}
}

func TestOriginAllowedExplicitList(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			CORS: CORSConfig{AllowedOrigins: []string{"https://a.example.com", "https://b.example.com"}},
		},
	}
	if got := cfg.OriginAllowed("https://a.example.com"); got != "https://a.example.com" {
		t.Fatalf("expected match, got %q", got)
	}
	if got := cfg.OriginAllowed("https://evil.example.com"); got != "" {
		t.Fatalf("expected disallow, got %q", got)
	}
	if got := cfg.OriginAllowed(""); got != "" {
		t.Fatalf("expected empty origin to be ignored, got %q", got)
	}
}
