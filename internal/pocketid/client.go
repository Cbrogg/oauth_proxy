package pocketid

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"litellm-oauth-facade/internal/config"
)

var (
	ErrUnparseable      = errors.New("jwt unparseable")
	ErrInvalidSignature = errors.New("jwt invalid signature")
	ErrInvalidIssuer    = errors.New("jwt invalid issuer")
	ErrExpired          = errors.New("jwt expired")
	ErrWrongType        = errors.New("jwt wrong type")
	ErrNotYetValid      = errors.New("jwt not yet valid")
)

type AccessTokenClaims struct {
	jwt.RegisteredClaims
	Type string `json:"type"`
}

type Client struct {
	cfg        *config.PocketIDConfig
	httpClient *http.Client
	log        *slog.Logger

	mu              sync.RWMutex
	discoveryJSON   json.RawMessage
	discoveryLoaded time.Time
	jwksKeys        map[string]*rsa.PublicKey
	jwksLoaded      time.Time
}

func NewClient(cfg *config.PocketIDConfig, log *slog.Logger) *Client {
	return &Client{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 15 * time.Second},
		log:        log,
		jwksKeys:   make(map[string]*rsa.PublicKey),
	}
}

func (c *Client) Bootstrap(ctx context.Context) error {
	if err := c.refreshDiscovery(ctx); err != nil {
		return fmt.Errorf("discovery bootstrap: %w", err)
	}
	if err := c.refreshJWKS(ctx); err != nil {
		return fmt.Errorf("jwks bootstrap: %w", err)
	}
	go c.backgroundRefresh()
	return nil
}

func (c *Client) backgroundRefresh() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		_ = c.maybeRefreshDiscovery(ctx)
		_ = c.maybeRefreshJWKS(ctx)
		cancel()
	}
}

func (c *Client) maybeRefreshDiscovery(ctx context.Context) error {
	c.mu.RLock()
	stale := time.Since(c.discoveryLoaded) > c.cfg.DiscoveryCacheTTL
	c.mu.RUnlock()
	if !stale {
		return nil
	}
	if err := c.refreshDiscovery(ctx); err != nil {
		c.log.Warn("discovery refresh failed", "error", err)
		return err
	}
	return nil
}

func (c *Client) maybeRefreshJWKS(ctx context.Context) error {
	c.mu.RLock()
	stale := time.Since(c.jwksLoaded) > c.cfg.JWKSCacheTTL
	c.mu.RUnlock()
	if !stale {
		return nil
	}
	if err := c.refreshJWKS(ctx); err != nil {
		c.log.Warn("jwks refresh failed", "error", err)
		return err
	}
	return nil
}

func (c *Client) refreshDiscovery(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.DiscoveryURL, nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("discovery status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.discoveryJSON = json.RawMessage(body)
	c.discoveryLoaded = time.Now()
	c.mu.Unlock()
	return nil
}

func (c *Client) refreshJWKS(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.JWKSURI, nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks status %d", resp.StatusCode)
	}
	var jwks jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return err
	}
	keys := make(map[string]*rsa.PublicKey)
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		pub, err := parseRSAPublicKey(k.N, k.E)
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return errors.New("no rsa keys in jwks")
	}
	c.mu.Lock()
	c.jwksKeys = keys
	c.jwksLoaded = time.Now()
	c.mu.Unlock()
	return nil
}

type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func parseRSAPublicKey(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, err
	}
	n := new(big.Int).SetBytes(nBytes)
	var eInt int
	for _, b := range eBytes {
		eInt = eInt<<8 + int(b)
	}
	return &rsa.PublicKey{N: n, E: eInt}, nil
}

func (c *Client) DiscoveryJSON() json.RawMessage {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.discoveryJSON
}

func (c *Client) HasValidJWKS() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.jwksKeys) > 0
}

func (c *Client) JWKSStale() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.jwksKeys) == 0 {
		return true
	}
	return time.Since(c.jwksLoaded) > c.cfg.JWKSCacheTTL
}

func (c *Client) DiscoveryStale() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.discoveryJSON) == 0 {
		return true
	}
	return time.Since(c.discoveryLoaded) > c.cfg.DiscoveryCacheTTL
}

func (c *Client) Validate(tokenString string, requireType string, issuer string, clockSkew time.Duration) (*AccessTokenClaims, error) {
	c.mu.RLock()
	keys := c.jwksKeys
	c.mu.RUnlock()

	claims := &AccessTokenClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, fmt.Errorf("unexpected alg %s", t.Method.Alg())
		}
		kid, _ := t.Header["kid"].(string)
		if kid != "" {
			key, ok := keys[kid]
			if !ok {
				return nil, fmt.Errorf("no jwks key for kid %q", kid)
			}
			return key, nil
		}
		// No kid: only acceptable while there is a single key, otherwise key
		// selection is ambiguous and must not be guessed.
		if len(keys) == 1 {
			for _, key := range keys {
				return key, nil
			}
		}
		return nil, errors.New("no kid in token with multiple jwks keys")
	}, jwt.WithLeeway(clockSkew))

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			if token != nil {
				if c, ok := token.Claims.(*AccessTokenClaims); ok {
					return c, ErrExpired
				}
			}
			return nil, ErrExpired
		}
		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, ErrNotYetValid
		}
		if errors.Is(err, jwt.ErrTokenSignatureInvalid) || errors.Is(err, jwt.ErrTokenUnverifiable) {
			return nil, ErrInvalidSignature
		}
		return nil, ErrUnparseable
	}

	if !token.Valid {
		return nil, ErrInvalidSignature
	}

	if claims.Issuer != issuer {
		return nil, ErrInvalidIssuer
	}

	if claims.Type != requireType {
		return claims, ErrWrongType
	}

	return claims, nil
}

func (c *Client) FetchUserinfo(ctx context.Context, accessToken string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.UserinfoEndpoint, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

// SetJWKSForTest injects keys for unit tests.
func (c *Client) SetJWKSForTest(keys map[string]*rsa.PublicKey) {
	c.mu.Lock()
	c.jwksKeys = keys
	c.jwksLoaded = time.Now()
	c.mu.Unlock()
}

func (c *Client) SetDiscoveryForTest(data json.RawMessage) {
	c.mu.Lock()
	c.discoveryJSON = data
	c.discoveryLoaded = time.Now()
	c.mu.Unlock()
}
