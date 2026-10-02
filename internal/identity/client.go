package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"litellm-oauth-facade/internal/config"
	"litellm-oauth-facade/internal/pocketid"
)

var (
	ErrUserinfoUnauthorized = errors.New("userinfo unauthorized")
	ErrUserinfoUnavailable  = errors.New("userinfo unavailable")
	ErrSubMismatch          = errors.New("userinfo sub mismatch")
	ErrEmailMismatch        = errors.New("userinfo email mismatch")
)

type Userinfo struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
}

type Client struct {
	cfg    *config.Config
	pocket *pocketid.Client

	mu    sync.RWMutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	userinfo  Userinfo
	expiresAt time.Time
}

func NewClient(cfg *config.Config, pocket *pocketid.Client) *Client {
	return &Client{
		cfg:    cfg,
		pocket: pocket,
		cache:  make(map[string]cacheEntry),
	}
}

func (c *Client) Resolve(ctx context.Context, accessToken string, claims *pocketid.AccessTokenClaims, user *config.ResolvedUser) (*Userinfo, error) {
	key := cacheKey(claims, accessToken)

	c.mu.RLock()
	if entry, ok := c.cache[key]; ok && time.Now().Before(entry.expiresAt) {
		c.mu.RUnlock()
		if err := c.crossCheck(entry.userinfo, claims, user); err != nil {
			return nil, err
		}
		return &entry.userinfo, nil
	}
	c.mu.RUnlock()

	body, status, err := c.pocket.FetchUserinfo(ctx, accessToken)
	if err != nil {
		return nil, ErrUserinfoUnavailable
	}
	switch status {
	case 401, 403:
		return nil, ErrUserinfoUnauthorized
	case 200:
		// continue
	default:
		if status >= 500 {
			return nil, ErrUserinfoUnavailable
		}
		return nil, ErrUserinfoUnavailable
	}

	var info Userinfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("parse userinfo: %w", err)
	}

	if err := c.crossCheck(info, claims, user); err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.cache[key] = cacheEntry{
		userinfo:  info,
		expiresAt: time.Now().Add(c.cfg.PocketID.UserinfoCacheTTL),
	}
	c.mu.Unlock()

	return &info, nil
}

func (c *Client) crossCheck(info Userinfo, claims *pocketid.AccessTokenClaims, user *config.ResolvedUser) error {
	if info.Sub != claims.Subject {
		return ErrSubMismatch
	}
	if info.Email != "" && !strings.EqualFold(info.Email, user.Email) {
		return ErrEmailMismatch
	}
	return nil
}

func cacheKey(claims *pocketid.AccessTokenClaims, accessToken string) string {
	if claims.ID != "" {
		return claims.Subject + ":" + claims.ID
	}
	sum := sha256.Sum256([]byte(accessToken))
	return claims.Subject + ":" + hex.EncodeToString(sum[:8])
}
