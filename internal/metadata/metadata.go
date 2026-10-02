package metadata

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"litellm-oauth-facade/internal/config"
	"litellm-oauth-facade/internal/pocketid"
)

type Service struct {
	cfg    *config.Config
	pocket *pocketid.Client
}

func New(cfg *config.Config, pocket *pocketid.Client) *Service {
	return &Service{cfg: cfg, pocket: pocket}
}

type protectedResource struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ScopesSupported        []string `json:"scopes_supported"`
}

func (s *Service) ProtectedResource(toolsetName string) protectedResource {
	return protectedResource{
		Resource:               s.cfg.ResourceURI(toolsetName),
		AuthorizationServers:   []string{s.cfg.PocketID.Issuer},
		BearerMethodsSupported: []string{"header"},
		ScopesSupported:        []string{"openid", "profile", "email"},
	}
}

func (s *Service) HandleProtectedResource(w http.ResponseWriter, r *http.Request, toolsetName string) {
	s.writeJSON(w, s.ProtectedResource(toolsetName))
}

func (s *Service) HandleOIDCMirror(w http.ResponseWriter, r *http.Request) {
	data := s.pocket.DiscoveryJSON()
	if len(data) == 0 {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Service) writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(v)
}

func Challenge(cfg *config.Config, toolsetName string) string {
	publicURL := strings.TrimRight(cfg.Server.PublicURL, "/")
	suffix := cfg.MetadataSuffix(toolsetName)
	metaURL := fmt.Sprintf("%s/.well-known/oauth-protected-resource/%s", publicURL, suffix)
	return fmt.Sprintf(`Bearer resource_metadata="%s", scope="openid profile email"`, metaURL)
}

func AudienceMatch(claims *pocketid.AccessTokenClaims, allowed map[string]struct{}) bool {
	for _, aud := range claims.Audience {
		if _, ok := allowed[aud]; ok {
			return true
		}
	}
	return false
}

func Subject(claims *pocketid.AccessTokenClaims) string {
	if claims == nil {
		return ""
	}
	return claims.Subject
}

func TokenAudienceStrings(claims *pocketid.AccessTokenClaims) []string {
	if claims == nil {
		return nil
	}
	return []string(claims.Audience)
}

// ParseUnverifiedClaims is only for tests.
func ParseUnverifiedClaims(token string) (*pocketid.AccessTokenClaims, error) {
	parser := jwt.NewParser()
	claims := &pocketid.AccessTokenClaims{}
	_, _, err := parser.ParseUnverified(token, claims)
	return claims, err
}
