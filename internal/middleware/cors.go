package middleware

import (
	"net/http"
	"strconv"

	"litellm-oauth-facade/internal/config"
)

// CORS injects a best-practice CORS policy for every response and short-circuits
// browser preflight (OPTIONS) requests.
//
// The policy is derived from cfg.Server.CORS:
//   - Access-Control-Allow-Origin is the configured origin, or the request
//     origin reflected when no explicit list is set. When AllowCredentials is
//     enabled and no explicit origin list is configured, the request origin is
//     echoed so the browser still honours credentials.
//   - OPTIONS preflight replies 204 with Access-Control-Allow-Methods,
//     Access-Control-Allow-Headers and Access-Control-Max-Age.
//   - Every browser response carries Access-Control-Allow-Origin and a
//     Vary: Origin header, so intermediaries cache per-origin correctly.
func CORS(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			allowOrigin := cfg.OriginAllowed(origin)

			if allowOrigin != "" {
				h := w.Header()
				h.Add("Vary", "Origin")
				h.Set("Access-Control-Allow-Origin", allowOrigin)
				if cfg.Server.CORS.AllowCredentials {
					h.Set("Access-Control-Allow-Credentials", "true")
				}
			}

			if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
				h := w.Header()
				h.Add("Vary", "Access-Control-Request-Method")
				h.Add("Vary", "Access-Control-Request-Headers")
				h.Set("Access-Control-Allow-Methods", cfg.AllowedMethodsHeader())
				if reqHeaders := r.Header.Get("Access-Control-Request-Headers"); reqHeaders != "" {
					if allowed := cfg.AllowedHeadersHeader(); allowed == "*" {
						h.Set("Access-Control-Allow-Headers", reqHeaders)
					} else {
						h.Set("Access-Control-Allow-Headers", allowed)
					}
					h.Add("Vary", "Access-Control-Request-Headers")
				}
				if maxAge := cfg.CorsMaxAgeSeconds(); maxAge > 0 {
					h.Set("Access-Control-Max-Age", strconv.FormatInt(maxAge, 10))
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
