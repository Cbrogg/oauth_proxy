package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"
	"litellm-oauth-facade/internal/authctx"
	"litellm-oauth-facade/internal/config"
	"litellm-oauth-facade/internal/metrics"
)

// defaultScopes advertises the OAuth scopes ChatGPT will request. They mirror
// the scopes_supported documented in the protected resource metadata.
var defaultScopes = []string{"openid", "profile", "email"}

func NewHandler(upstream config.ToolsetRuntime, toolsetBasePath string, toolsetName string, log *slog.Logger) http.Handler {
	target, _ := url.Parse(strings.TrimRight(upstream.BaseURL, "/"))
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ResponseHeaderTimeout: upstream.Timeout,
	}

	// Inject per-tool _meta.securitySchemes (oauth2) into tools/list responses
	// so ChatGPT treats the tools as OAuth-gated and runs the linking flow.
	// Only buffer and rewrite tools/list frames; other methods keep streaming.
	proxy.ModifyResponse = func(resp *http.Response) error {
		if resp.Request == nil {
			return nil
		}
		method := resp.Request.Context().Value(ctxMethodKey{}).(string)
		if method != "tools/list" {
			return nil
		}
		body, err := readAllLimited(resp.Body, 8<<20)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		rewrite := streamedRewriteFn(resp.Header.Get("Content-Type"), defaultScopes)
		rewritten, err := rewrite(body)
		if err != nil {
			resp.Body = io.NopCloser(bytes.NewReader(body))
			resp.ContentLength = int64(len(body))
			return nil
		}
		resp.Body = io.NopCloser(bytes.NewReader(rewritten))
		resp.ContentLength = int64(len(rewritten))
		return nil
	}

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		incomingPath := req.Context().Value(ctxPathKey{}).(string)
		incomingQuery := req.Context().Value(ctxQueryKey{}).(string)

		originalDirector(req)
		req.URL.Path = upstreamPath(upstream, toolsetBasePath, target.Path, incomingPath)
		req.URL.RawQuery = incomingQuery
		req.Host = target.Host
		modifyRequest(req, upstream)
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		if log != nil {
			attrs := []any{
				"toolset", toolsetName,
				"method", r.Method,
				"path", r.URL.Path,
				"error", err.Error(),
			}
			if id := chimw.GetReqID(r.Context()); id != "" {
				attrs = append(attrs, "request_id", id)
			}
			if user := authctx.User(r.Context()); user != nil {
				attrs = append(attrs, "user", user.Email)
			}
			log.Error("upstream proxy error", attrs...)
		}
		if err != nil && (strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline")) {
			http.Error(w, http.StatusText(http.StatusGatewayTimeout), http.StatusGatewayTimeout)
			return
		}
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ctx := context.WithValue(r.Context(), ctxPathKey{}, r.URL.Path)
		ctx = context.WithValue(ctx, ctxQueryKey{}, r.URL.RawQuery)
		ctx = context.WithValue(ctx, ctxMethodKey{}, mcpMethod(r))
		if body := r.Body; body != nil {
			defer body.Close()
		}
		sw := &statusCapture{ResponseWriter: w}
		proxy.ServeHTTP(sw, r.WithContext(ctx))
		metrics.Global().ObserveProxy(toolsetName, time.Since(start))

		if log != nil && sw.status >= 400 {
			attrs := []any{
				"toolset", toolsetName,
				"method", r.Method,
				"path", r.URL.Path,
				"upstream_status", sw.status,
				"upstream_url", strings.TrimRight(upstream.BaseURL, "/") + r.URL.Path,
				"duration_ms", time.Since(start).Milliseconds(),
			}
			if id := chimw.GetReqID(r.Context()); id != "" {
				attrs = append(attrs, "request_id", id)
			}
			if user := authctx.User(r.Context()); user != nil {
				attrs = append(attrs, "user", user.Email)
			}
			log.Warn("upstream error response", attrs...)
		}
	})
}

type statusCapture struct {
	http.ResponseWriter
	status int
}

func (w *statusCapture) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusCapture) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusCapture) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *statusCapture) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusCapture) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying ResponseWriter does not implement http.Hijacker")
	}
	return h.Hijack()
}

func (w *statusCapture) Push(target string, opts *http.PushOptions) error {
	if p, ok := w.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}

func (w *statusCapture) ReadFrom(r io.Reader) (int64, error) {
	if rf, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}
	return io.Copy(w.ResponseWriter, r)
}

type ctxPathKey struct{}
type ctxQueryKey struct{}
type ctxMethodKey struct{}

// mcpMethod peeks the JSON-RPC method from the request body without consuming
// it, so the reverse proxy can still forward the full body upstream.
func mcpMethod(r *http.Request) string {
	if r.Body == nil {
		return ""
	}
	body, err := readAllLimited(r.Body, 1<<20)
	if err != nil {
		return ""
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	var msg struct {
		Method string `json:"method"`
	}
	if err := json.Unmarshal(body, &msg); err != nil {
		return ""
	}
	return msg.Method
}

// upstreamPath computes the path to send upstream.
//
// For LiteLLM toolsets (no per-toolset base_url) the facade path is preserved
// as-is so LiteLLM can route by its own /toolset/<name>/mcp layout. For a
// toolset with an explicit base_url the incoming /toolset/<name>/mcp prefix is
// replaced by the upstream path prefix, mapping onto any Streamable HTTP MCP
// endpoint, e.g. /api/mcp.
func upstreamPath(upstream config.ToolsetRuntime, toolsetBasePath, upstreamPath, incomingPath string) string {
	if !upstream.CustomPath {
		return incomingPath
	}
	suffix := strings.TrimPrefix(incomingPath, toolsetBasePath)
	return strings.TrimRight(upstreamPath, "/") + suffix
}

func modifyRequest(req *http.Request, upstream config.ToolsetRuntime) {
	if upstream.ForwardAccessToken {
		// Pass the caller's validated access token upstream untouched. Drop
		// the duplicated forwarded header the proxy may have added.
		req.Header.Del("X-Forwarded-Access-Token")
		return
	}
	for _, h := range []string{"Authorization", "Cookie", "X-Forwarded-Access-Token"} {
		req.Header.Del(h)
	}
	for k := range req.Header {
		if strings.EqualFold(k, "x-litellm-api-key") {
			req.Header.Del(k)
		}
	}
	if headers := authctx.InjectHeaders(req.Context()); headers != nil {
		for k, v := range headers {
			req.Header.Set(k, v)
		}
	}
}
