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

// sweepEvery bounds how often the background goroutine reclaims expired cache
// entries. It is intentionally independent of the configured TTL so the sweeper
// never starves under a long TTL or thrashes under a short one.
const sweepEvery = time.Minute

type Client struct {
	cfg    *config.Config
	pocket *pocketid.Client

	mu    sync.RWMutex
	cache map[string]cacheEntry

	stopCh chan struct{}
	doneCh chan struct{}
}

type cacheEntry struct {
	userinfo  Userinfo
	expiresAt time.Time
}

func NewClient(cfg *config.Config, pocket *pocketid.Client) *Client {
	c := &Client{
		cfg:    cfg,
		pocket: pocket,
		cache:  make(map[string]cacheEntry),
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
	go c.sweepLoop()
	return c
}

// Close stops the background sweeper and waits for it to exit. It is safe to
// call from multiple goroutines; repeated calls are no-ops.
func (c *Client) Close() {
	c.mu.Lock()
	select {
	case <-c.stopCh:
		c.mu.Unlock()
		<-c.doneCh
		return
	default:
		close(c.stopCh)
	}
	c.mu.Unlock()
	<-c.doneCh
}

func (c *Client) sweepLoop() {
	defer close(c.doneCh)
	ticker := time.NewTicker(sweepEvery)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.sweepExpired()
		}
	}
}

func (c *Client) sweepExpired() {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, entry := range c.cache {
		if now.After(entry.expiresAt) {
			delete(c.cache, key)
		}
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
