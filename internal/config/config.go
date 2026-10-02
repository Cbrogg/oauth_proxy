package config

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

var envPattern = regexp.MustCompile(`\$\{([A-Z0-9_]+)\}`)

type Config struct {
	Server   ServerConfig             `yaml:"server"`
	LiteLLM  LiteLLMConfig            `yaml:"litellm"`
	PocketID PocketIDConfig           `yaml:"pocket_id"`
	Identity IdentityConfig           `yaml:"identity"`
	Toolsets map[string]ToolsetConfig `yaml:"toolsets"`
	Users    map[string]UserConfig    `yaml:"users"`

	Index *UserIndex `yaml:"-"`
}

type ServerConfig struct {
	Listen    string `yaml:"listen"`
	PublicURL string `yaml:"public_url"`
	LogLevel  string `yaml:"log_level"`
}

type LiteLLMConfig struct {
	BaseURL          string        `yaml:"base_url"`
	Timeout          time.Duration `yaml:"timeout"`
	SharedKeyAllowed bool          `yaml:"shared_key_allowed"`
}

type PocketIDConfig struct {
	Issuer            string                `yaml:"issuer"`
	DiscoveryURL      string                `yaml:"discovery_url"`
	DiscoveryCacheTTL time.Duration         `yaml:"discovery_cache_ttl"`
	JWKSURI           string                `yaml:"jwks_uri"`
	JWKSCacheTTL      time.Duration         `yaml:"jwks_cache_ttl"`
	UserinfoEndpoint  string                `yaml:"userinfo_endpoint"`
	UserinfoCacheTTL  time.Duration         `yaml:"userinfo_cache_ttl"`
	TokenValidation   TokenValidationConfig `yaml:"token_validation"`
}

type TokenValidationConfig struct {
	AcceptedClientIDs []string      `yaml:"accepted_client_ids"`
	RequireTokenType  string        `yaml:"require_token_type"`
	ClockSkew         time.Duration `yaml:"clock_skew"`
}

type IdentityConfig struct {
	MatchBy string `yaml:"match_by"`
}

type ToolsetConfig struct{}

type UserConfig struct {
	Sub      string                        `yaml:"sub"`
	Toolsets map[string]ToolsetGrantConfig `yaml:"toolsets"`
}

type ToolsetGrantConfig struct {
	Headers map[string]string `yaml:"headers"`
}

type ResolvedUser struct {
	Email    string
	Sub      string
	Toolsets map[string]ToolsetGrantConfig
}

type UserIndex struct {
	BySub map[string]*ResolvedUser
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	expanded := expandEnv(string(data))

	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	cfg.Index = cfg.buildIndex()
	return &cfg, nil
}

func expandEnv(s string) string {
	return envPattern.ReplaceAllStringFunc(s, func(match string) string {
		name := envPattern.FindStringSubmatch(match)[1]
		if v, ok := os.LookupEnv(name); ok {
			return v
		}
		return match
	})
}

func (c *Config) validate() error {
	if c.Server.PublicURL == "" {
		return fmt.Errorf("server.public_url is required")
	}
	if _, err := url.Parse(c.Server.PublicURL); err != nil {
		return fmt.Errorf("server.public_url invalid: %w", err)
	}
	if c.Server.Listen == "" {
		c.Server.Listen = ":8080"
	}
	if c.Server.LogLevel == "" {
		c.Server.LogLevel = "info"
	}

	if c.LiteLLM.BaseURL == "" {
		return fmt.Errorf("litellm.base_url is required")
	}
	u, err := url.Parse(c.LiteLLM.BaseURL)
	if err != nil {
		return fmt.Errorf("litellm.base_url invalid: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("litellm.base_url must be scheme+host")
	}
	if u.Path != "" && u.Path != "/" {
		return fmt.Errorf("litellm.base_url must not have a path")
	}
	if c.LiteLLM.Timeout == 0 {
		c.LiteLLM.Timeout = 60 * time.Second
	}

	if c.PocketID.Issuer == "" {
		return fmt.Errorf("pocket_id.issuer is required")
	}
	if len(c.PocketID.TokenValidation.AcceptedClientIDs) == 0 {
		return fmt.Errorf("pocket_id.token_validation.accepted_client_ids is required")
	}
	if c.PocketID.TokenValidation.RequireTokenType == "" {
		c.PocketID.TokenValidation.RequireTokenType = "oauth-access-token"
	}
	if c.PocketID.TokenValidation.ClockSkew == 0 {
		c.PocketID.TokenValidation.ClockSkew = time.Minute
	}
	if c.PocketID.DiscoveryCacheTTL == 0 {
		c.PocketID.DiscoveryCacheTTL = 5 * time.Minute
	}
	if c.PocketID.JWKSCacheTTL == 0 {
		c.PocketID.JWKSCacheTTL = time.Hour
	}
	if c.PocketID.UserinfoCacheTTL == 0 {
		c.PocketID.UserinfoCacheTTL = 5 * time.Minute
	}

	if len(c.Toolsets) == 0 {
		return fmt.Errorf("toolsets must not be empty")
	}

	if len(c.Users) == 0 {
		return fmt.Errorf("users must not be empty")
	}

	seenSubs := make(map[string]string)

	for email, user := range c.Users {
		if user.Sub == "" {
			return fmt.Errorf("users.%s.sub is required", email)
		}
		if prev, ok := seenSubs[user.Sub]; ok {
			return fmt.Errorf("duplicate sub %q for users %s and %s", user.Sub, prev, email)
		}
		seenSubs[user.Sub] = email

		if len(user.Toolsets) == 0 {
			return fmt.Errorf("users.%s must have at least one toolset grant", email)
		}

		for toolsetName, grant := range user.Toolsets {
			if _, ok := c.Toolsets[toolsetName]; !ok {
				return fmt.Errorf("users.%s.toolsets.%s references unknown toolset", email, toolsetName)
			}
			key := grant.Headers["x-litellm-api-key"]
			if key == "" {
				return fmt.Errorf("users.%s.toolsets.%s.headers.x-litellm-api-key is required", email, toolsetName)
			}
		}
	}

	return nil
}

func (c *Config) buildIndex() *UserIndex {
	idx := &UserIndex{BySub: make(map[string]*ResolvedUser)}
	for email, user := range c.Users {
		idx.BySub[user.Sub] = &ResolvedUser{
			Email:    email,
			Sub:      user.Sub,
			Toolsets: user.Toolsets,
		}
	}
	return idx
}

func (c *Config) ToolsetBasePath(name string) string {
	return fmt.Sprintf("/toolset/%s/mcp", name)
}

func (c *Config) ResourceURI(name string) string {
	return strings.TrimRight(c.Server.PublicURL, "/") + c.ToolsetBasePath(name)
}

func (c *Config) MetadataSuffix(name string) string {
	return strings.TrimPrefix(c.ToolsetBasePath(name), "/")
}

func (idx *UserIndex) Lookup(sub string) (*ResolvedUser, bool) {
	u, ok := idx.BySub[sub]
	return u, ok
}

func (u *ResolvedUser) Grant(toolset string) (map[string]string, bool) {
	g, ok := u.Toolsets[toolset]
	if !ok {
		return nil, false
	}
	return g.Headers, true
}

func (c *Config) IsWhitelisted(sub string) bool {
	_, ok := c.Index.Lookup(sub)
	return ok
}

func (c *Config) AcceptedClientIDSet() map[string]struct{} {
	set := make(map[string]struct{}, len(c.PocketID.TokenValidation.AcceptedClientIDs))
	for _, id := range c.PocketID.TokenValidation.AcceptedClientIDs {
		set[id] = struct{}{}
	}
	return set
}
