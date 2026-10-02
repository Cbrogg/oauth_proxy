package authctx

import (
	"context"

	"litellm-oauth-facade/internal/config"
	"litellm-oauth-facade/internal/pocketid"
)

type contextKey int

const (
	keyToolset contextKey = iota
	keyAccessToken
	keyClaims
	keyUser
	keyInjectHeaders
)

func WithToolset(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, keyToolset, name)
}

func Toolset(ctx context.Context) string {
	v, _ := ctx.Value(keyToolset).(string)
	return v
}

func WithAccessToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, keyAccessToken, token)
}

func AccessToken(ctx context.Context) string {
	v, _ := ctx.Value(keyAccessToken).(string)
	return v
}

func WithClaims(ctx context.Context, claims *pocketid.AccessTokenClaims) context.Context {
	return context.WithValue(ctx, keyClaims, claims)
}

func Claims(ctx context.Context) *pocketid.AccessTokenClaims {
	v, _ := ctx.Value(keyClaims).(*pocketid.AccessTokenClaims)
	return v
}

func WithUser(ctx context.Context, user *config.ResolvedUser) context.Context {
	return context.WithValue(ctx, keyUser, user)
}

func User(ctx context.Context) *config.ResolvedUser {
	v, _ := ctx.Value(keyUser).(*config.ResolvedUser)
	return v
}

func WithInjectHeaders(ctx context.Context, headers map[string]string) context.Context {
	return context.WithValue(ctx, keyInjectHeaders, headers)
}

func InjectHeaders(ctx context.Context) map[string]string {
	v, _ := ctx.Value(keyInjectHeaders).(map[string]string)
	return v
}
