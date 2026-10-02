package pocketid

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"litellm-oauth-facade/internal/config"
)

func testRSAKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key, "test-kid"
}

func signToken(t *testing.T, key *rsa.PrivateKey, kid string, claims AccessTokenClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	s, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func testClient(t *testing.T, keys map[string]*rsa.PublicKey) *Client {
	t.Helper()
	cfg := configStub()
	client := NewClient(cfg, nil)
	client.SetJWKSForTest(keys)
	return client
}

func TestValidateAccessToken(t *testing.T) {
	priv, kid := testRSAKey(t)
	client := testClient(t, map[string]*rsa.PublicKey{kid: &priv.PublicKey})

	now := time.Now()
	claims := AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://id.example.com",
			Subject:   "00000000-0000-4000-8000-000000000000",
			Audience:  jwt.ClaimStrings{"f3df1491-e6cd-411f-8b74-4219f2953536"},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        "6b78844d-02f6-44b3-879a-45c6b57c96d9",
		},
		Type: "oauth-access-token",
	}
	token := signToken(t, priv, kid, claims)

	got, err := client.Validate(token, "oauth-access-token", "https://id.example.com", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != claims.Subject {
		t.Fatalf("sub: %s", got.Subject)
	}
}

func TestRejectIDTokenType(t *testing.T) {
	priv, kid := testRSAKey(t)
	client := testClient(t, map[string]*rsa.PublicKey{kid: &priv.PublicKey})

	now := time.Now()
	claims := AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://id.example.com",
			Subject:   "00000000-0000-4000-8000-000000000000",
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		Type: "id-token",
	}
	token := signToken(t, priv, kid, claims)

	_, err := client.Validate(token, "oauth-access-token", "https://id.example.com", time.Minute)
	if err != ErrWrongType {
		t.Fatalf("expected ErrWrongType, got %v", err)
	}
}

func TestUnknownKidRejected(t *testing.T) {
	priv, kid := testRSAKey(t)
	client := testClient(t, map[string]*rsa.PublicKey{kid: &priv.PublicKey})

	now := time.Now()
	claims := AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://id.example.com",
			Subject:   "00000000-0000-4000-8000-000000000000",
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		Type: "oauth-access-token",
	}
	// Sign with a key the client does not know under a made-up kid.
	token := signToken(t, priv, "someone-else-kid", claims)

	_, err := client.Validate(token, "oauth-access-token", "https://id.example.com", time.Minute)
	if err == nil {
		t.Fatal("expected rejection for unknown kid")
	}
}

func TestMissingKidWithMultipleKeysRejected(t *testing.T) {
	privA, kidA := testRSAKey(t)
	privB, kidB := testRSAKey(t)
	client := testClient(t, map[string]*rsa.PublicKey{
		kidA: &privA.PublicKey,
		kidB: &privB.PublicKey,
	})

	claims := AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://id.example.com",
			Subject:   "00000000-0000-4000-8000-000000000000",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Type: "oauth-access-token",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	s, err := token.SignedString(privA)
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Validate(s, "oauth-access-token", "https://id.example.com", time.Minute)
	if err == nil {
		t.Fatal("expected rejection for missing kid with multiple keys")
	}
}

func TestInvalidSignature(t *testing.T) {
	otherPriv, kid := testRSAKey(t)
	client := testClient(t, map[string]*rsa.PublicKey{kid: &otherPriv.PublicKey})

	signer, _ := testRSAKey(t)
	now := time.Now()
	claims := AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://id.example.com",
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		Type: "oauth-access-token",
	}
	token := signToken(t, signer, kid, claims)

	_, err := client.Validate(token, "oauth-access-token", "https://id.example.com", time.Minute)
	if err != ErrInvalidSignature && err != ErrUnparseable {
		t.Fatalf("expected signature error, got %v", err)
	}
}

func TestExpiredTokenReturnsTrustedClaims(t *testing.T) {
	priv, kid := testRSAKey(t)
	client := testClient(t, map[string]*rsa.PublicKey{kid: &priv.PublicKey})

	now := time.Now()
	claims := AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://id.example.com",
			Subject:   "00000000-0000-4000-8000-000000000000",
			ExpiresAt: jwt.NewNumericDate(now.Add(-time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now.Add(-2 * time.Hour)),
		},
		Type: "oauth-access-token",
	}
	token := signToken(t, priv, kid, claims)

	got, err := client.Validate(token, "oauth-access-token", "https://id.example.com", time.Minute)
	if err != ErrExpired {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
	if got == nil || got.Subject != claims.Subject {
		t.Fatalf("expected trusted sub on expiry")
	}
}

func configStub() *config.PocketIDConfig {
	return &config.PocketIDConfig{
		Issuer:            "https://id.example.com",
		DiscoveryCacheTTL: 5 * time.Minute,
		JWKSCacheTTL:      time.Hour,
	}
}

// Ensure fixture JSON is valid.
func TestAccessTokenFixtureShape(t *testing.T) {
	raw := `{
    "aud": ["f3df1491-e6cd-411f-8b74-4219f2953536"],
    "iss": "https://id.example.com",
    "sub": "00000000-0000-4000-8000-000000000000",
    "type": "oauth-access-token"
  }`
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
}
