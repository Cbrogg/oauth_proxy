package middleware

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMCPAuthenticateBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/toolset/yuvomi_anton/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":7,"method":"tools/call"}`))
	req.Header.Set("Content-Type", "application/json")

	challenge := `Bearer resource_metadata="https://mcp-auth.tale-tales.ru/.well-known/oauth-protected-resource/toolset/yuvomi_anton/mcp", scope="openid profile email offline_access"`
	out, ok := mcpAuthenticateBody(req, challenge)
	if !ok {
		t.Fatal("expected MCP authenticate body for JSON-RPC POST")
	}

	var resp struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Result  struct {
			Meta    map[string][]string `json:"_meta"`
			IsError bool                `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.JSONRPC != "2.0" {
		t.Fatalf("jsonrpc = %q", resp.JSONRPC)
	}
	if resp.ID != 7 {
		t.Fatalf("id = %d, want 7", resp.ID)
	}
	if !resp.Result.IsError {
		t.Fatal("isError must be true")
	}
	chals := resp.Result.Meta["mcp/www_authenticate"]
	if len(chals) == 0 {
		t.Fatal("missing mcp/www_authenticate meta")
	}
	if !strings.Contains(chals[0], "oauth-protected-resource") {
		t.Fatalf("challenge missing resource_metadata: %s", chals[0])
	}
}

func TestMCPAuthenticateBodyNonMCP(t *testing.T) {
	// GET requests are not MCP tool calls
	req := httptest.NewRequest(http.MethodGet, "/toolset/x/mcp", nil)
	if _, ok := mcpAuthenticateBody(req, "challenge"); ok {
		t.Fatal("GET must not produce MCP authenticate body")
	}

	// POST without JSON id is not a tool request
	req2 := httptest.NewRequest(http.MethodPost, "/toolset/x/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","method":"initialize"}`))
	req2.Header.Set("Content-Type", "application/json")
	if _, ok := mcpAuthenticateBody(req2, "challenge"); ok {
		t.Fatal("request without id must not produce MCP authenticate body")
	}
}

func TestWrite401SetsMCPBodyForToolRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/toolset/yuvomi_anton/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":9,"method":"tools/call"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	challenge := `Bearer resource_metadata="https://mcp-auth.tale-tales.ru/.well-known/oauth-protected-resource/toolset/yuvomi_anton/mcp", scope="openid profile email offline_access"`
	write401(rec, req, challenge)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != challenge {
		t.Fatalf("WWW-Authenticate = %q", got)
	}
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), "mcp/www_authenticate") {
		t.Fatalf("response body missing mcp/www_authenticate: %s", body)
	}
}
