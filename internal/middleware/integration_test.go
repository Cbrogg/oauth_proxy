package middleware_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"litellm-oauth-facade/internal/config"
	"litellm-oauth-facade/internal/httpserver"
	"litellm-oauth-facade/internal/identity"
	"litellm-oauth-facade/internal/pocketid"
)

type testEnv struct {
	Server   *httptest.Server
	Config   *config.Config
	Priv     *rsa.PrivateKey
	Kid      string
	ClientID string
}

func newTestEnv(t *testing.T, userinfo http.HandlerFunc, litellm http.HandlerFunc) *testEnv {
	t.Helper()
	t.Setenv("CHATGPT_POCKET_ID_CLIENT_ID", "f3df1491-e6cd-411f-8b74-4219f2953536")
	t.Setenv("LITELLM_KEY_USER1_MEMOS", "sk-user1-memos")
	t.Setenv("POCKET_ID_USER_SUB", "YOUR-POCKET-ID-USER-SUB")

	cfg, err := config.Load(filepath.Join("..", "..", "config.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	kid := "test-kid"

	oidc := httptest.NewServer(nil)
	oidc.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": oidc.URL})
		case "/.well-known/jwks.json":
			w.WriteHeader(http.StatusOK)
		case "/api/oidc/userinfo":
			userinfo(w, r)
		default:
			http.NotFound(w, r)
		}
	})
	t.Cleanup(oidc.Close)

	cfg.PocketID.Issuer = oidc.URL
	cfg.PocketID.DiscoveryURL = oidc.URL + "/.well-known/openid-configuration"
	cfg.PocketID.JWKSURI = oidc.URL + "/.well-known/jwks.json"
	cfg.PocketID.UserinfoEndpoint = oidc.URL + "/api/oidc/userinfo"

	litellmSrv := httptest.NewServer(litellm)
	t.Cleanup(litellmSrv.Close)
	cfg.LiteLLM.BaseURL = litellmSrv.URL

	pocket := pocketid.NewClient(&cfg.PocketID, nil)
	pocket.SetJWKSForTest(map[string]*rsa.PublicKey{kid: &priv.PublicKey})
	pocket.SetDiscoveryForTest(json.RawMessage(`{"issuer":"` + oidc.URL + `"}`))

	identityClient := identity.NewClient(cfg, pocket)
	srv := httpserver.New(cfg, pocket, identityClient, nil)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	return &testEnv{
		Server:   ts,
		Config:   cfg,
		Priv:     priv,
		Kid:      kid,
		ClientID: cfg.PocketID.TokenValidation.AcceptedClientIDs[0],
	}
}

func (e *testEnv) token(sub, tokenType string, exp time.Time, aud string) string {
	claims := pocketid.AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    e.Config.PocketID.Issuer,
			Subject:   sub,
			Audience:  jwt.ClaimStrings{aud},
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        "jti-test",
		},
		Type: tokenType,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = e.Kid
	s, err := tok.SignedString(e.Priv)
	if err != nil {
		panic(err)
	}
	return s
}

func (e *testEnv) postMCP(token string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, e.Server.URL+"/toolset/memos/mcp", strings.NewReader(`{}`))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return http.DefaultClient.Do(req)
}

func TestNoBearer401(t *testing.T) {
	env := newTestEnv(t,
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) },
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) },
	)

	resp, err := env.postMCP("")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if resp.Header.Get("WWW-Authenticate") == "" {
		t.Fatal("expected WWW-Authenticate")
	}
}

func TestUnknownUser403LiteLLMNotCalled(t *testing.T) {
	var litellmCalled atomic.Bool
	env := newTestEnv(t,
		func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"sub":   "unknown-sub",
				"email": "unknown@example.com",
			})
		},
		func(w http.ResponseWriter, r *http.Request) { litellmCalled.Store(true) },
	)

	token := env.token("unknown-sub", "oauth-access-token", time.Now().Add(time.Hour), env.ClientID)
	resp, err := env.postMCP(token)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
	if litellmCalled.Load() {
		t.Fatal("litellm should not be called")
	}
}

func TestWhitelistedUserProxiesWithLiteLLMKey(t *testing.T) {
	var gotKey string
	env := newTestEnv(t,
		func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"sub":   "YOUR-POCKET-ID-USER-SUB",
				"email": "user@example.com",
			})
		},
		func(w http.ResponseWriter, r *http.Request) {
			gotKey = r.Header.Get("x-litellm-api-key")
			if r.Header.Get("Authorization") != "" {
				t.Error("authorization must be stripped")
			}
			w.WriteHeader(http.StatusOK)
		},
	)

	token := env.token("YOUR-POCKET-ID-USER-SUB", "oauth-access-token", time.Now().Add(time.Hour), env.ClientID)
	resp, err := env.postMCP(token)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
	if gotKey != "Bearer sk-user1-memos" {
		t.Fatalf("key %q", gotKey)
	}
}

func TestWrongAud403(t *testing.T) {
	env := newTestEnv(t,
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) },
		func(w http.ResponseWriter, r *http.Request) { t.Error("litellm called") },
	)

	token := env.token("YOUR-POCKET-ID-USER-SUB", "oauth-access-token", time.Now().Add(time.Hour), "wrong-client")
	resp, err := env.postMCP(token)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestExpiredWhitelistedUser401(t *testing.T) {
	env := newTestEnv(t,
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) },
		func(w http.ResponseWriter, r *http.Request) { t.Error("litellm called") },
	)

	token := env.token("YOUR-POCKET-ID-USER-SUB", "oauth-access-token", time.Now().Add(-time.Hour), env.ClientID)
	resp, err := env.postMCP(token)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestOptions204(t *testing.T) {
	env := newTestEnv(t,
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) },
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) },
	)

	req, _ := http.NewRequest(http.MethodOptions, env.Server.URL+"/toolset/memos/mcp", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestTrailingSlashNoRedirect(t *testing.T) {
	env := newTestEnv(t,
		func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"sub":   "YOUR-POCKET-ID-USER-SUB",
				"email": "user@example.com",
			})
		},
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) },
	)

	token := env.token("YOUR-POCKET-ID-USER-SUB", "oauth-access-token", time.Now().Add(time.Hour), env.ClientID)
	req, _ := http.NewRequest(http.MethodPost, env.Server.URL+"/toolset/memos/mcp/", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusPermanentRedirect {
		t.Fatalf("unexpected redirect %d", resp.StatusCode)
	}
}

func TestStripClientLiteLLMKey(t *testing.T) {
	var gotKey string
	env := newTestEnv(t,
		func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"sub":   "YOUR-POCKET-ID-USER-SUB",
				"email": "user@example.com",
			})
		},
		func(w http.ResponseWriter, r *http.Request) {
			gotKey = r.Header.Get("x-litellm-api-key")
			w.WriteHeader(http.StatusOK)
		},
	)

	token := env.token("YOUR-POCKET-ID-USER-SUB", "oauth-access-token", time.Now().Add(time.Hour), env.ClientID)
	req, _ := http.NewRequest(http.MethodPost, env.Server.URL+"/toolset/memos/mcp", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-litellm-api-key", "Bearer attacker-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if gotKey != "Bearer sk-user1-memos" {
		t.Fatalf("expected config key, got %q", gotKey)
	}
}

func TestReadyzWithJWKS(t *testing.T) {
	env := newTestEnv(t,
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) },
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) },
	)

	resp, err := http.Get(env.Server.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
}
