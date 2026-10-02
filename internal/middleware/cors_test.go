package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"litellm-oauth-facade/internal/config"
)

func corsConfig(allowedOrigins []string, credentials bool) *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			CORS: config.CORSConfig{
				AllowedOrigins:   allowedOrigins,
				AllowedMethods:   []string{"GET", "POST", "DELETE", "OPTIONS"},
				AllowedHeaders:   []string{"Authorization", "Content-Type"},
				AllowCredentials: credentials,
				MaxAge:           time.Hour,
			},
		},
	}
}

func TestCORSPreflight(t *testing.T) {
	cfg := corsConfig([]string{"https://app.example.com"}, false)
	handler := CORS(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodOptions, "/toolset/memos/mcp", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Authorization, Content-Type")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want 204", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Fatalf("allow-origin = %q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Methods"); got == "" {
		t.Fatal("missing allow-methods")
	}
	if got := rec.Header().Get("Access-Control-Allow-Headers"); got == "" {
		t.Fatal("missing allow-headers")
	}
	if got := rec.Header().Get("Access-Control-Max-Age"); got == "" {
		t.Fatal("missing max-age")
	}
}

func TestCORSDisallowedOriginGetsNoHeaders(t *testing.T) {
	cfg := corsConfig([]string{"https://app.example.com"}, false)
	handler := CORS(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/toolset/memos/mcp", nil)
	req.Header.Set("Origin", "https://evil.example.com")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("disallowed origin must not receive allow-origin")
	}
}

func TestCORSReflectsAnyOriginByDefault(t *testing.T) {
	cfg := corsConfig(nil, false)
	handler := CORS(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/toolset/memos/mcp", nil)
	req.Header.Set("Origin", "https://any.example.com")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://any.example.com" {
		t.Fatalf("reflect allow-origin = %q", got)
	}
	if !hasVary(rec, "Origin") {
		t.Fatal("missing Vary: Origin")
	}
}

func TestCORSNoOriginBypasses(t *testing.T) {
	cfg := corsConfig(nil, false)
	handler := CORS(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/toolset/memos/mcp", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func hasVary(rec *httptest.ResponseRecorder, field string) bool {
	for _, v := range rec.Header().Values("Vary") {
		if v == field {
			return true
		}
	}
	return false
}
