package metadata_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"litellm-oauth-facade/internal/config"
	"litellm-oauth-facade/internal/metadata"
	"litellm-oauth-facade/internal/pocketid"
)

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	t.Setenv("CHATGPT_POCKET_ID_CLIENT_ID", "f3df1491-e6cd-411f-8b74-4219f2953536")
	t.Setenv("LITELLM_KEY_USER1_MEMOS", "sk-test")
	cfg, err := config.Load(filepath.Join("..", "..", "config.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestProtectedResourceGolden(t *testing.T) {
	cfg := testConfig(t)
	svc := metadata.New(cfg, pocketid.NewClient(&cfg.PocketID, nil))

	body := svc.ProtectedResource("memos")
	data, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')

	goldenPath := filepath.Join("testdata", "protected_resource_memos.golden.json")
	golden, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(golden) {
		t.Fatalf("golden mismatch:\n%s", string(data))
	}
}

func TestChallengeGolden(t *testing.T) {
	cfg := testConfig(t)
	got := metadata.Challenge(cfg, "memos")
	want := `Bearer resource_metadata="https://YOUR-PUBLIC-FACADE-DOMAIN/.well-known/oauth-protected-resource/toolset/memos/mcp", scope="openid profile email"`
	if got != want {
		t.Fatalf("challenge:\n%s", got)
	}
}

func TestProtectedResourcePathAAndB(t *testing.T) {
	cfg := testConfig(t)
	pocket := pocketid.NewClient(&cfg.PocketID, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		meta := metadata.New(cfg, pocket)
		switch r.URL.Path {
		case "/.well-known/oauth-protected-resource/toolset/memos/mcp":
			meta.HandleProtectedResource(w, r, "memos")
		case "/toolset/memos/mcp/.well-known/oauth-protected-resource":
			meta.HandleProtectedResource(w, r, "memos")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	for _, path := range []string{
		"/.well-known/oauth-protected-resource/toolset/memos/mcp",
		"/toolset/memos/mcp/.well-known/oauth-protected-resource",
	} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s status %d", path, resp.StatusCode)
		}
	}
}

func TestUnknownWellKnownSuffix404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.well-known/oauth-protected-resource/unknown") {
			http.NotFound(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/.well-known/oauth-protected-resource/unknown/path")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d", resp.StatusCode)
	}
}
