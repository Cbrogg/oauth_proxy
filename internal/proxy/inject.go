package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

// securityScheme describes the OAuth 2.0 requirement ChatGPT needs per tool
// so it marks a tool as OAuth-gated and runs the linking flow. Mirrors the
// OpenAPI securitySchemes shape documented by OpenAI for MCP servers.
type securityScheme struct {
	Type   string   `json:"type"`
	Scopes []string `json:"scopes,omitempty"`
}

// oauthScheme builds the securityScheme entry to advertise for tools.
func oauthScheme(scopes []string) securityScheme {
	return securityScheme{Type: "oauth2", Scopes: scopes}
}

// isToolsList reports whether the JSON-RPC frame is a tools/list result
// (i.e. its result carries a "tools" array).
func isToolsList(result map[string]any) bool {
	_, ok := result["tools"].([]any)
	return ok
}

// rewriteSSE injects the securitySchemes advertisement into every tick of an
// SSE streamed MCP response whose frame is a tools/list result. Non-matching
// frames are passed through untouched.
func rewriteSSE(body []byte, scopes []string) ([]byte, error) {
	lines := bytes.Split(body, []byte("\n"))
	out := make([][]byte, 0, len(lines))
	for _, line := range lines {
		if !bytes.HasPrefix(line, []byte("data:")) {
			out = append(out, line)
			continue
		}
		payload := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
		if len(payload) == 0 {
			out = append(out, line)
			continue
		}
		var frame struct {
			ID     any            `json:"id"`
			Result map[string]any `json:"result"`
		}
		if err := json.Unmarshal(payload, &frame); err != nil || frame.Result == nil {
			out = append(out, line)
			continue
		}
		if !isToolsList(frame.Result) {
			out = append(out, line)
			continue
		}
		injectSecuritySchemes(frame.Result, scopes)
		reEncoded, err := json.Marshal(frame)
		if err != nil {
			out = append(out, line)
			continue
		}
		out = append(out, append([]byte("data: "), reEncoded...))
	}
	return bytes.Join(out, []byte("\n")), nil
}

// rewriteJSON injects the securitySchemes advertisement into a plain JSON
// MCP response (non-SSE) that is a tools/list result.
func rewriteJSON(body []byte, scopes []string) ([]byte, error) {
	var frame struct {
		ID     any            `json:"id"`
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal(body, &frame); err != nil || frame.Result == nil {
		return body, nil
	}
	if !isToolsList(frame.Result) {
		return body, nil
	}
	injectSecuritySchemes(frame.Result, scopes)
	return json.Marshal(frame)
}

// injectSecuritySchemes adds _meta.securitySchemes (oauth2) to each tool in a
// tools/list result. Existing per-tool _meta is preserved; the securitySchemes
// key is replaced.
func injectSecuritySchemes(result map[string]any, scopes []string) {
	tools, ok := result["tools"].([]any)
	if !ok {
		return
	}
	scheme := oauthScheme(scopes)
	for i := range tools {
		tool, ok := tools[i].(map[string]any)
		if !ok {
			continue
		}
		meta, ok := tool["_meta"].(map[string]any)
		if !ok {
			meta = map[string]any{}
			tool["_meta"] = meta
		}
		meta["securitySchemes"] = []securityScheme{scheme}
	}
}

// streamedRewriteFn returns a body rewrite func for MCP responses, choosing
// SSE vs JSON handling based on the upstream Content-Type.
func streamedRewriteFn(ct string, scopes []string) func([]byte) ([]byte, error) {
	if strings.Contains(ct, "text/event-stream") {
		return func(b []byte) ([]byte, error) { return rewriteSSE(b, scopes) }
	}
	return func(b []byte) ([]byte, error) { return rewriteJSON(b, scopes) }
}

// readAllLimited reads the body up to a hard cap to avoid unbounded buffering
// when rewriting tool list payloads.
func readAllLimited(r io.Reader, limit int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, limit))
}
