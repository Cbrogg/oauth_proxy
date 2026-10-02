package middleware

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"litellm-oauth-facade/internal/authctx"
	"litellm-oauth-facade/internal/config"
	"litellm-oauth-facade/internal/identity"
	"litellm-oauth-facade/internal/metadata"
	"litellm-oauth-facade/internal/metrics"
	"litellm-oauth-facade/internal/pocketid"
)

type Deps struct {
	Config   *config.Config
	PocketID *pocketid.Client
	Identity *identity.Client
	Meta     *metadata.Service
	Metrics  *metrics.Registry
	Log      *slog.Logger
}

func RequireBearer(cfg *config.Config, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			toolset := authctx.Toolset(r.Context())
			auth := r.Header.Get("Authorization")
			if auth == "" || !strings.HasPrefix(auth, "Bearer ") || strings.TrimSpace(strings.TrimPrefix(auth, "Bearer ")) == "" {
				metrics.Global().AuthFailure("no_bearer")
				logAuthDeny(log, r, http.StatusUnauthorized, "no_bearer")
				write401(w, metadata.Challenge(cfg, toolset))
				return
			}
			token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
			ctx := authctx.WithAccessToken(r.Context(), token)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func JWTValidate(deps *Deps) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			toolset := authctx.Toolset(r.Context())
			token := authctx.AccessToken(r.Context())
			tv := deps.Config.PocketID.TokenValidation

			claims, err := deps.PocketID.Validate(token, tv.RequireTokenType, deps.Config.PocketID.Issuer, tv.ClockSkew)
			if err != nil {
				extra := []any{"error", err.Error()}
				if claims != nil {
					extra = append(extra, "sub", claims.Subject)
				}

				switch {
				case errors.Is(err, pocketid.ErrInvalidSignature),
					errors.Is(err, pocketid.ErrInvalidIssuer),
					errors.Is(err, pocketid.ErrUnparseable),
					errors.Is(err, pocketid.ErrNotYetValid):
					metrics.Global().AuthFailure("invalid_jwt")
					logAuthDeny(deps.Log, r, http.StatusUnauthorized, "invalid_jwt", extra...)
					write401(w, metadata.Challenge(deps.Config, toolset))
					return
				case errors.Is(err, pocketid.ErrExpired), errors.Is(err, pocketid.ErrWrongType):
					if claims != nil && deps.Config.IsWhitelisted(claims.Subject) {
						metrics.Global().AuthFailure("invalid_jwt")
						logAuthDeny(deps.Log, r, http.StatusUnauthorized, "invalid_jwt", extra...)
						write401(w, metadata.Challenge(deps.Config, toolset))
						return
					}
					metrics.Global().AuthFailure("invalid_jwt")
					logAuthDeny(deps.Log, r, http.StatusForbidden, "invalid_jwt", extra...)
					write403(w)
					return
				default:
					metrics.Global().AuthFailure("invalid_jwt")
					logAuthDeny(deps.Log, r, http.StatusUnauthorized, "invalid_jwt", extra...)
					write401(w, metadata.Challenge(deps.Config, toolset))
					return
				}
			}

			ctx := authctx.WithClaims(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func ClientIDAllowlist(deps *Deps) func(http.Handler) http.Handler {
	allowed := deps.Config.AcceptedClientIDSet()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := authctx.Claims(r.Context())
			if !metadata.AudienceMatch(claims, allowed) {
				metrics.Global().AuthFailure("wrong_aud")
				logAuthDeny(deps.Log, r, http.StatusForbidden, "wrong_aud",
					"sub", claims.Subject,
					"token_aud", metadata.TokenAudienceStrings(claims),
					"allowed_client_ids", deps.Config.PocketID.TokenValidation.AcceptedClientIDs,
				)
				write403(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func UserinfoResolve(deps *Deps) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			toolset := authctx.Toolset(r.Context())
			token := authctx.AccessToken(r.Context())
			claims := authctx.Claims(r.Context())

			user, ok := deps.Config.Index.Lookup(claims.Subject)
			if !ok {
				metrics.Global().AuthFailure("not_whitelisted")
				logAuthDeny(deps.Log, r, http.StatusForbidden, "not_whitelisted",
					"sub", claims.Subject,
				)
				write403(w)
				return
			}

			_, err := deps.Identity.Resolve(r.Context(), token, claims, user)
			if err != nil {
				switch {
				case errors.Is(err, identity.ErrUserinfoUnauthorized):
					metrics.Global().AuthFailure("userinfo_unauthorized")
					logAuthDeny(deps.Log, r, http.StatusUnauthorized, "userinfo_unauthorized",
						"sub", claims.Subject,
						"user", user.Email,
					)
					write401(w, metadata.Challenge(deps.Config, toolset))
				case errors.Is(err, identity.ErrSubMismatch):
					metrics.Global().AuthFailure("userinfo_sub_mismatch")
					logAuthDeny(deps.Log, r, http.StatusUnauthorized, "userinfo_sub_mismatch",
						"sub", claims.Subject,
						"user", user.Email,
					)
					write401(w, metadata.Challenge(deps.Config, toolset))
				case errors.Is(err, identity.ErrEmailMismatch):
					metrics.Global().AuthFailure("email_mismatch")
					logAuthDeny(deps.Log, r, http.StatusForbidden, "email_mismatch",
						"sub", claims.Subject,
						"user", user.Email,
					)
					write403(w)
				case errors.Is(err, identity.ErrUserinfoUnavailable):
					logAuthDeny(deps.Log, r, http.StatusServiceUnavailable, "userinfo_unavailable",
						"sub", claims.Subject,
						"user", user.Email,
						"error", err.Error(),
					)
					write503(w)
				default:
					logAuthDeny(deps.Log, r, http.StatusServiceUnavailable, "userinfo_error",
						"sub", claims.Subject,
						"user", user.Email,
						"error", err.Error(),
					)
					write503(w)
				}
				return
			}

			ctx := authctx.WithUser(r.Context(), user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func UserWhitelist(deps *Deps, toolsetName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := authctx.User(r.Context())
			if user == nil {
				metrics.Global().AuthFailure("not_whitelisted")
				logAuthDeny(deps.Log, r, http.StatusForbidden, "not_whitelisted", "stage", "grant")
				write403(w)
				return
			}
			headers, ok := user.Grant(toolsetName)
			if !ok {
				metrics.Global().AuthFailure("no_grant")
				logAuthDeny(deps.Log, r, http.StatusForbidden, "no_grant",
					"sub", user.Sub,
					"user", user.Email,
					"toolset", toolsetName,
				)
				write403(w)
				return
			}
			logAuthSuccess(deps.Log, r, "user", user.Email, "sub", user.Sub)
			ctx := authctx.WithInjectHeaders(r.Context(), headers)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func write401(w http.ResponseWriter, challenge string) {
	w.Header().Set("WWW-Authenticate", challenge)
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}

func write403(w http.ResponseWriter) {
	http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
}

func write503(w http.ResponseWriter) {
	http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
}

func Options204() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}
}
