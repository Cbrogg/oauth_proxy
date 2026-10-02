package identity

import (
	"testing"
	"time"

	"litellm-oauth-facade/internal/config"
	"litellm-oauth-facade/internal/pocketid"
)

func TestSweepRemovesExpiredEntries(t *testing.T) {
	cfg := &config.Config{
		PocketID: config.PocketIDConfig{UserinfoCacheTTL: time.Minute},
	}
	c := NewClient(cfg, &pocketid.Client{})

	c.cache["fresh"] = cacheEntry{
		userinfo:  Userinfo{Sub: "fresh", Email: "fresh@example.com"},
		expiresAt: time.Now().Add(time.Hour),
	}
	c.cache["stale"] = cacheEntry{
		userinfo:  Userinfo{Sub: "stale", Email: "stale@example.com"},
		expiresAt: time.Now().Add(-time.Minute),
	}

	c.sweepExpired()

	if _, ok := c.cache["fresh"]; !ok {
		t.Fatal("expected fresh entry to survive sweep")
	}
	if _, ok := c.cache["stale"]; ok {
		t.Fatal("expected stale entry to be swept")
	}
}

func TestCloseStopsSweeper(t *testing.T) {
	cfg := &config.Config{
		PocketID: config.PocketIDConfig{UserinfoCacheTTL: time.Minute},
	}
	c := NewClient(cfg, &pocketid.Client{})

	done := make(chan struct{})
	go func() {
		c.Close()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return")
	}

	// Must be safe to call again.
	c.Close()
}
