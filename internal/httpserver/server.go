package httpserver

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"litellm-oauth-facade/internal/authctx"
	"litellm-oauth-facade/internal/config"
	"litellm-oauth-facade/internal/identity"
	"litellm-oauth-facade/internal/metadata"
	"litellm-oauth-facade/internal/middleware"
	"litellm-oauth-facade/internal/pocketid"
	"litellm-oauth-facade/internal/proxy"
)

type Server struct {
	cfg    *config.Config
	pocket *pocketid.Client
	router chi.Router
}

func New(cfg *config.Config, pocket *pocketid.Client, identityClient *identity.Client, log *slog.Logger) *Server {
	meta := metadata.New(cfg, pocket)
	deps := &middleware.Deps{
		Config:   cfg,
		PocketID: pocket,
		Identity: identityClient,
		Meta:     meta,
		Log:      log,
	}

	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(middleware.AccessLog(log))

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	r.Method(http.MethodOptions, "/healthz", middleware.Options204())

	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if !pocket.HasValidJWKS() {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
	r.Method(http.MethodOptions, "/readyz", middleware.Options204())

	r.Handle("/metrics", promhttp.Handler())
	r.Method(http.MethodOptions, "/metrics", middleware.Options204())

	for name := range cfg.Toolsets {
		registerToolset(r, cfg, meta, deps, name, log)
	}

	return &Server{cfg: cfg, pocket: pocket, router: r}
}

func (s *Server) Handler() http.Handler {
	return s.router
}

func registerToolset(r chi.Router, cfg *config.Config, meta *metadata.Service, deps *middleware.Deps, name string, log *slog.Logger) {
	base := cfg.ToolsetBasePath(name)
	suffix := cfg.MetadataSuffix(name)

	// Path A metadata
	r.Get("/.well-known/oauth-protected-resource/"+suffix, func(w http.ResponseWriter, r *http.Request) {
		meta.HandleProtectedResource(w, r, name)
	})
	r.Method(http.MethodOptions, "/.well-known/oauth-protected-resource/"+suffix, middleware.Options204())

	r.Get("/.well-known/openid-configuration/"+suffix, meta.HandleOIDCMirror)
	r.Method(http.MethodOptions, "/.well-known/openid-configuration/"+suffix, middleware.Options204())

	r.Get("/.well-known/oauth-authorization-server/"+suffix, meta.HandleOIDCMirror)
	r.Method(http.MethodOptions, "/.well-known/oauth-authorization-server/"+suffix, middleware.Options204())

	// Path B metadata
	r.Get(base+"/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		meta.HandleProtectedResource(w, r, name)
	})
	r.Method(http.MethodOptions, base+"/.well-known/oauth-protected-resource", middleware.Options204())

	r.Get(base+"/.well-known/openid-configuration", meta.HandleOIDCMirror)
	r.Method(http.MethodOptions, base+"/.well-known/openid-configuration", middleware.Options204())

	r.Get(base+"/.well-known/oauth-authorization-server", meta.HandleOIDCMirror)
	r.Method(http.MethodOptions, base+"/.well-known/oauth-authorization-server", middleware.Options204())

	proxyHandler := proxy.NewHandler(cfg, name, log)

	withToolset := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := authctx.WithToolset(r.Context(), name)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}

	authChain := r.With(
		withToolset,
		middleware.RequireBearer(cfg, log),
		middleware.JWTValidate(deps),
		middleware.ClientIDAllowlist(deps),
		middleware.UserinfoResolve(deps),
		middleware.UserWhitelist(deps, name),
	)

	for _, path := range []string{base, base + "/"} {
		authChain.Method(http.MethodPost, path, proxyHandler)
		authChain.Method(http.MethodGet, path, proxyHandler)
		authChain.Method(http.MethodDelete, path, proxyHandler)
		r.Method(http.MethodOptions, path, middleware.Options204())
	}
}
