package proxy

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"litellm-oauth-facade/internal/authctx"
	"litellm-oauth-facade/internal/config"
)

func TestStatusCapturePreservesFlusher(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusCapture{ResponseWriter: rec}

	if _, ok := any(sw).(http.Flusher); !ok {
		t.Fatal("statusCapture must implement http.Flusher for streamable MCP responses")
	}
	sw.Flush()
}

func TestStatusCaptureReportsStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusCapture{ResponseWriter: rec}

	sw.WriteHeader(http.StatusServiceUnavailable)
	if sw.status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", sw.status, http.StatusServiceUnavailable)
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("underlying code = %d", rec.Code)
	}
}

func TestStatusCaptureDefaultsToWrite(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusCapture{ResponseWriter: rec}

	_, _ = sw.Write([]byte("ok"))
	if sw.status != http.StatusOK {
		t.Fatalf("status = %d, want %d", sw.status, http.StatusOK)
	}
}

func TestStatusCaptureReadFromWithoutReaderFrom(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusCapture{ResponseWriter: rec}

	if _, ok := any(sw).(io.ReaderFrom); !ok {
		t.Fatal("statusCapture must implement io.ReaderFrom")
	}
	n, err := sw.ReadFrom(strings.NewReader("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Fatalf("n = %d, want 5", n)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("underlying code = %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Body.String() != "hello" {
		t.Fatalf("body = %q, want hello", rec.Body.String())
	}
}

func TestStatusCaptureUnwrap(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusCapture{ResponseWriter: rec}

	u, ok := any(sw).(interface{ Unwrap() http.ResponseWriter })
	if !ok {
		t.Fatal("statusCapture must expose Unwrap")
	}
	if u.Unwrap() != rec {
		t.Fatal("Unwrap did not return the underlying writer")
	}
}

func TestRewriteSSEInjectsSecuritySchemes(t *testing.T) {
	sse := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"a\",\"inputSchema\":{}},{\"name\":\"b\",\"inputSchema\":{}}]}}\n\n"
	out, err := rewriteSSE([]byte(sse), defaultScopes)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "securitySchemes") {
		t.Fatalf("securitySchemes not injected: %s", out)
	}
	if !strings.Contains(string(out), `"type":"oauth2"`) {
		t.Fatalf("oauth2 scheme missing: %s", out)
	}
	var frame struct {
		Result struct {
			Tools []struct {
				Meta map[string]json.RawMessage `json:"_meta"`
			} `json:"tools"`
		} `json:"result"`
	}
	line := strings.Split(string(out), "\n")[1]
	if err := json.Unmarshal([]byte(strings.TrimPrefix(strings.TrimSpace(line), "data: ")), &frame); err != nil {
		t.Fatal(err)
	}
	for i, tool := range frame.Result.Tools {
		ss, ok := tool.Meta["securitySchemes"]
		if !ok {
			t.Fatalf("tool %d missing securitySchemes", i)
		}
		if !strings.Contains(string(ss), "openid") {
			t.Fatalf("tool %d scopes missing openid: %s", i, ss)
		}
	}
}

func TestRewriteSSEPreservesNonToolsFrame(t *testing.T) {
	sse := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"servers\":[{\"name\":\"s\"}]}}\n\n"
	out, err := rewriteSSE([]byte(sse), defaultScopes)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "securitySchemes") {
		t.Fatalf("should not inject into non-tools frame: %s", out)
	}
}

func TestRewriteJSONInjectsSecuritySchemes(t *testing.T) {
	in := `{"jsonrpc":"2.0","id":5,"result":{"tools":[{"name":"x","inputSchema":{}}]}}`
	out, err := rewriteJSON([]byte(in), defaultScopes)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "securitySchemes") {
		t.Fatalf("securitySchemes not injected: %s", out)
	}
}

func TestRewriteJSONNonToolsPassthrough(t *testing.T) {
	in := `{"jsonrpc":"2.0","id":6,"result":{"protocolVersion":"2025-11-25"}}`
	out, err := rewriteJSON([]byte(in), defaultScopes)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "securitySchemes") {
		t.Fatalf("should not inject into non-tools frame: %s", out)
	}
	if strings.TrimSpace(string(out)) != in {
		t.Fatalf("passthrough changed body: %s", out)
	}
}

func TestMCPMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/toolset/yuvomi_anton/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Content-Type", "application/json")
	if got := mcpMethod(req); got != "tools/list" {
		t.Fatalf("mcpMethod = %q, want tools/list", got)
	}
	// body must still be readable after peek
	buf, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(buf), "tools/list") {
		t.Fatalf("body consumed/mangled: %s", buf)
	}
}

func TestCustomUpstreamPathMappingAndTokenForwarding(t *testing.T) {
	var gotPath, gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a","inputSchema":{}}]}}`))
	}))
	defer upstream.Close()

	rt := config.ToolsetRuntime{
		BaseURL:            upstream.URL + "/api/mcp",
		Timeout:            10 * time.Second,
		ForwardAccessToken: true,
		CustomPath:         true,
	}
	h := NewHandler(rt, "/toolset/kryton/mcp", "kryton", slog.New(slog.DiscardHandler))

	req := httptest.NewRequest(http.MethodPost, "/toolset/kryton/mcp/session/1", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer pocket-id-token")
	req.Header.Set("Cookie", "session=x")
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)

	if gotPath != "/api/mcp/session/1" {
		t.Fatalf("upstream path = %q, want /api/mcp/session/1", gotPath)
	}
	if gotAuth != "Bearer pocket-id-token" {
		t.Fatalf("Authorization = %q, want forwarded bearer token", gotAuth)
	}
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d", resp.Code)
	}
	if !strings.Contains(resp.Body.String(), "securitySchemes") {
		t.Fatalf("tools/list body not rewritten with securitySchemes: %s", resp.Body.String())
	}
}

func TestLiteLLMUpstreamPreservesPathAndInjectsHeaders(t *testing.T) {
	var gotPath, gotAuth, gotKey string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotKey = r.Header.Get("x-litellm-api-key")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	rt := config.ToolsetRuntime{BaseURL: upstream.URL, Timeout: 10 * time.Second}
	h := NewHandler(rt, "/toolset/memos/mcp", "memos", slog.New(slog.DiscardHandler))

	req := httptest.NewRequest(http.MethodPost, "/toolset/memos/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer should-be-stripped")
	req = req.WithContext(authctx.WithInjectHeaders(req.Context(), map[string]string{"x-litellm-api-key": "Bearer sk-test"}))
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)

	if gotPath != "/toolset/memos/mcp" {
		t.Fatalf("upstream path = %q, want preserved /toolset/memos/mcp", gotPath)
	}
	if gotAuth != "" {
		t.Fatalf("Authorization = %q, want stripped", gotAuth)
	}
	if gotKey != "Bearer sk-test" {
		t.Fatalf("x-litellm-api-key = %q, want injected header", gotKey)
	}
}
