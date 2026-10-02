package proxy

import (
	"context"
	"log/slog"
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

func NewHandler(cfg *config.Config, toolsetName string, log *slog.Logger) http.Handler {
	target, _ := url.Parse(strings.TrimRight(cfg.LiteLLM.BaseURL, "/"))
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ResponseHeaderTimeout: cfg.LiteLLM.Timeout,
	}

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		incomingPath := req.Context().Value(ctxPathKey{}).(string)
		incomingQuery := req.Context().Value(ctxQueryKey{}).(string)

		originalDirector(req)
		req.URL.Path = incomingPath
		req.URL.RawQuery = incomingQuery
		req.Host = target.Host
		modifyRequest(req)
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
		sw := &statusCapture{ResponseWriter: w}
		proxy.ServeHTTP(sw, r.WithContext(ctx))
		metrics.Global().ObserveProxy(toolsetName, time.Since(start))

		if log != nil && sw.status >= 400 {
			attrs := []any{
				"toolset", toolsetName,
				"method", r.Method,
				"path", r.URL.Path,
				"upstream_status", sw.status,
				"upstream_url", strings.TrimRight(cfg.LiteLLM.BaseURL, "/") + r.URL.Path,
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

type ctxPathKey struct{}
type ctxQueryKey struct{}

func modifyRequest(req *http.Request) {
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
