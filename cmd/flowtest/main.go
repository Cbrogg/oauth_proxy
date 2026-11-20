// flowtest — локальный end-to-end прогон OAuth 2.0 authorization code flow
// против Pocket ID (issuer). Поднимает loopback HTTP-сервер, собрает URL
// авторизации (PKCE S256), открывает браузер и обменивает authorization code
// на токен в callback.
//
// Использование:
//
//	# конфиденциальный клиент (client_secret)
//	go run ./cmd/flowtest --mode=conf
//	# публичный клиент (без client_secret)
//	go run ./cmd/flowtest --mode=pub
//
// Флаги-оверрайды позволяют прогнать произвольный клиент:
//
//	go run ./cmd/flowtest --client-id=<id> --client-secret=<sec> --path=/cb
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const (
	baseScheme        = "http"
	callbackWaitMax   = 10 * time.Minute
	httpClientTimeout = 30 * time.Second
	defaultIssuer     = "https://id.tale-tales.ru"
	defaultScope      = "openid profile email offline_access"
)

// clientPreset — регистрируемый клиент.
type clientPreset struct {
	name         string
	clientID     string
	clientSecret string // пусто для публичного клиента
	path         string
}

type options struct {
	mode         string
	issuer       string
	resource     string
	scope        string
	bind         string // host:port, напр. 127.0.0.1:12345
	clientID     string
	clientSecret string
	path         string
	debug        bool
	dry          bool
}

func main() {
	opts := parseFlags()
	if err := run(context.Background(), opts); err != nil {
		fmt.Fprintln(os.Stderr, "flowtest:", err)
		os.Exit(1)
	}
}

func parseFlags() options {
	var o options
	flag.StringVar(&o.mode, "mode", "conf", "preset: conf (confidential) | pub (public)")
	flag.StringVar(&o.issuer, "issuer", defaultIssuer, "OAuth2/OIDC issuer (AS discovery base)")
	flag.StringVar(&o.resource, "resource", "", "RFC 8707 resource parameter (optional)")
	flag.StringVar(&o.scope, "scope", defaultScope, "requested scope")
	flag.StringVar(&o.bind, "bind", "127.0.0.1:12345", "loopback callback host:port")
	flag.StringVar(&o.clientID, "client-id", "", "override client_id")
	flag.StringVar(&o.clientSecret, "client-secret", "", "override client_secret")
	flag.StringVar(&o.path, "path", "", "override callback path")
	flag.BoolVar(&o.debug, "debug", false, "print full authorize URL and token response")
	flag.BoolVar(&o.dry, "dry", false, "print authorize URL and exit without starting the server")
	flag.Parse()
	if o.issuer == "" {
		fail("issuer is required")
	}
	return o
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "flowtest: "+format+"\n", args...)
	os.Exit(2)
}

func run(ctx context.Context, opts options) error {
	// 1. Клиент (preset или оверрайды).
	client, ok := resolveClient(opts)
	if !ok {
		return fmt.Errorf("unknown mode %q; want conf or pub", opts.mode)
	}
	redirectURI := redirectBase(opts.bind) + "/" + strings.TrimPrefix(client.path, "/")

	// 2. AS discovery.
	disc, err := discover(ctx, opts.issuer)
	if err != nil {
		return fmt.Errorf("discovery: %w", err)
	}
	fmt.Printf("issuer           : %s\n", disc.Issuer)
	fmt.Printf("authorization    : %s\n", disc.AuthorizationEndpoint)
	fmt.Printf("token            : %s\n", disc.TokenEndpoint)
	fmt.Printf("PKCE methods     : %v\n", disc.CodeChallengeMethods)

	// 3. PKCE.
	verifier := base64.RawURLEncoding.EncodeToString(randBytes(32))
	challenge := s256(verifier)

	if opts.dry {
		state := "flowtest-state-" + base64.RawURLEncoding.EncodeToString(randBytes(24))
		u := authorizeURL(disc, client, redirectURI, state, challenge, opts)
		fmt.Printf("---- authorize URL (dry run, not started) ----\n%s\n------------------------------------------------\n", u)
		return nil
	}

	// 4. Loopback callback server.
	state := "flowtest-state-" + base64.RawURLEncoding.EncodeToString(randBytes(24))
	tokens := make(chan *tokenResult, 1)
	errs := make(chan error, 1)
	srv := &http.Server{Addr: opts.bind}
	mux := http.NewServeMux()
	mux.HandleFunc(client.path, func(w http.ResponseWriter, r *http.Request) {
		handleCallback(ctx, w, r, disc, client, redirectURI, state, verifier, tokens, errs)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w,
			"flowtest callback server listening on %s\n\nOpen this URL in a browser to start the flow:\n%s",
			opts.bind, authorizeURL(disc, client, redirectURI, state, challenge, opts),
		)
	})
	srv.Handler = mux
	ln, err := net.Listen("tcp", opts.bind)
	if err != nil {
		return fmt.Errorf("listen %s: %w", opts.bind, err)
	}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- fmt.Errorf("callback server: %w", err)
		}
	}()
	defer srv.Close()
	fmt.Printf("callback server  : http://%s (redirect_uri %s)\n", opts.bind, redirectURI)

	// 5. Authorize URL + открыть браузер.
	authURL := authorizeURL(disc, client, redirectURI, state, challenge, opts)
	fmt.Printf("client_id        : %s\n", client.clientID)
	fmt.Printf("redirect_uri     : %s\n", redirectURI)
	if opts.resource != "" {
		fmt.Printf("resource         : %s\n", opts.resource)
	}
	fmt.Printf("\nOpening browser... if it did not open, paste manually:\n%s\n\n", authURL)
	if os.Getenv("FLOWTEST_NO_BROWSER") == "" {
		if err := openBrowser(authURL); err != nil {
			fmt.Printf("(auto-open failed: %v)\n", err)
		}
	}
	if opts.debug {
		fmt.Println("--- authorize URL ---")
		fmt.Println(authURL)
		fmt.Println("----------------------")
	}

	// 6. Ждём callback.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errs:
		return err
	case res := <-tokens:
		if res.err != nil {
			return fmt.Errorf("authorize/token error: %w", res.err)
		}
		printTokenResponse(res.resp)
		if err := saveTokens(res.resp, client.name); err != nil {
			fmt.Fprintf(os.Stderr, "write flowtest_tokens_%s.json: %v\n", client.name, err)
		}
		return nil
	case <-time.After(callbackWaitMax):
		return errors.New("timed out waiting for authorization callback")
	}
}

func resolveClient(o options) (clientPreset, bool) {
	switch strings.ToLower(o.mode) {
	case "conf", "confidential":
		c := clientPreset{
			name:         "conf",
			clientID:     "596b7e00-80b8-4638-a845-b788086d630c",
			clientSecret: "nhZ12AM44bF2vj4i4CI5pUlH9EDlwEeK",
			path:         "/auth_callback",
		}
		applyOverrides(&c, o)
		return c, true
	case "pub", "public":
		c := clientPreset{
			name:     "pub",
			clientID: "b84e6860-52a0-496b-90fa-01abbe706e0e",
			path:     "/auth_callback_pub",
		}
		applyOverrides(&c, o)
		return c, true
	default:
		return clientPreset{}, false
	}
}

func applyOverrides(c *clientPreset, o options) {
	if o.clientID != "" {
		c.clientID = o.clientID
		c.name = "custom"
	}
	if o.clientSecret != "" {
		c.clientSecret = o.clientSecret
	}
	if o.path != "" {
		c.path = o.path
	}
}

// --- Discovery -------------------------------------------------------------

type discoveryDoc struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	CodeChallengeMethods  []string `json:"code_challenge_methods_supported"`
}

func discover(ctx context.Context, issuer string) (*discoveryDoc, error) {
	u := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	var doc discoveryDoc
	if err := getJSON(ctx, u, &doc); err != nil {
		return nil, err
	}
	if doc.Issuer == "" || doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" {
		return nil, fmt.Errorf("incomplete discovery document from %s", u)
	}
	return &doc, nil
}

func getJSON(ctx context.Context, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s -> %s: %s", url, resp.Status, strings.TrimSpace(string(b)))
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return err
	}
	return nil
}

// --- Authorize URL ---------------------------------------------------------

func authorizeURL(disc *discoveryDoc, c clientPreset, redirectURI, state, challenge string, o options) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", c.clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", o.scope)
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	if o.resource != "" {
		q.Set("resource", o.resource)
	}
	return disc.AuthorizationEndpoint + "?" + q.Encode()
}

// --- PKCE ---

func s256(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// --- Callback + token exchange --------------------------------------------

type tokenResult struct {
	resp *tokenResponse
	err  error
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token"`
	Raw          map[string]any
}

func handleCallback(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	disc *discoveryDoc,
	c clientPreset,
	redirectURI, state, verifier string,
	tokens chan<- *tokenResult,
	errs chan<- error,
) {
	q := r.URL.Query()
	if got := q.Get("state"); got != state {
		writeHTML(w, http.StatusBadRequest, "flowtest", fmt.Sprintf("state mismatch (got %q)", got))
		return
	}
	if e := q.Get("error"); e != "" {
		desc := q.Get("error_description")
		writeHTML(w, http.StatusBadRequest, "flowtest authorization error",
			"<b>"+html.EscapeString(e)+"</b><br>"+html.EscapeString(desc))
		tokens <- &tokenResult{err: fmt.Errorf("authorization error %s: %s", e, desc)}
		return
	}
	code := q.Get("code")
	if code == "" {
		writeHTML(w, http.StatusBadRequest, "flowtest", "no authorization code in callback")
		return
	}

	resp, err := exchangeCode(ctx, disc.TokenEndpoint, c, redirectURI, code, verifier)
	if err != nil {
		writeHTML(w, http.StatusBadGateway, "flowtest token exchange error",
			"<pre>"+html.EscapeString(err.Error())+"</pre>")
		tokens <- &tokenResult{err: err}
		return
	}
	writeHTML(w, http.StatusOK, "flowtest: token received", renderTokenHTML(resp))
	tokens <- &tokenResult{resp: resp}
}

func exchangeCode(ctx context.Context, tokenEndpoint string, c clientPreset, redirectURI, code, verifier string) (*tokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", c.clientID)
	form.Set("code_verifier", verifier)
	if c.clientSecret != "" {
		form.Set("client_secret", c.clientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	var tr tokenResponse
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if err := json.Unmarshal(body, &tr); err != nil {
			return nil, fmt.Errorf("parse token response (%s): %w", resp.Status, err)
		}
		if tr.AccessToken == "" {
			return nil, fmt.Errorf("token response missing access_token: %s", body)
		}
		_ = json.Unmarshal(body, &tr.Raw)
		return &tr, nil
	}

	var terr struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &terr)
	desc := terr.ErrorDescription
	if desc == "" {
		desc = strings.TrimSpace(string(body))
	}
	return nil, fmt.Errorf("token endpoint %s: %s (error=%s)", resp.Status, desc, terr.Error)
}

func printTokenResponse(tr *tokenResponse) {
	var b strings.Builder
	b.WriteString("\n===== TOKEN RECEIVED =====\n")
	fmt.Fprintf(&b, "token_type      : %s\n", tr.TokenType)
	fmt.Fprintf(&b, "expires_in      : %d s\n", tr.ExpiresIn)
	fmt.Fprintf(&b, "scope           : %s\n", tr.Scope)
	fmt.Fprintf(&b, "access_token    : %s\n", tr.AccessToken)
	if tr.RefreshToken != "" {
		fmt.Fprintf(&b, "refresh_token   : %s\n", tr.RefreshToken)
	}
	if tr.IDToken != "" {
		fmt.Fprintf(&b, "id_token        : %s\n", tr.IDToken)
	}
	b.WriteString("===========================\n")
	fmt.Println(b.String())
}

func renderTokenHTML(tr *tokenResponse) string {
	v, _ := json.MarshalIndent(tr, "", "  ")
	return "<p>Authorization successful. You can close this tab.</p><pre>" +
		html.EscapeString(string(v)) + "</pre>"
}

func writeHTML(w http.ResponseWriter, status int, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, "<!doctype html><html><head><meta charset=utf-8><title>%s</title></head>"+
		"<body><h2>%s</h2>%s</body></html>",
		html.EscapeString(title), html.EscapeString(title), body)
}

func saveTokens(tr *tokenResponse, name string) error {
	payload, err := json.MarshalIndent(tr, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile("flowtest_tokens_"+name+".json", payload, 0o600)
}

// --- misc ------------------------------------------------------------------

func httpClient() *http.Client {
	return &http.Client{
		Timeout: httpClientTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
}

// redirectBase возвращает loopback-базу для redirect_uri по --bind.
// Нормализует пустой host до 127.0.0.1, иначе callback будет уходить
// на неверный интерфейс.
func redirectBase(bind string) string {
	host, port, err := net.SplitHostPort(bind)
	if err != nil || port == "" {
		return baseScheme + "://127.0.0.1"
	}
	if host == "" || host == "*" {
		host = "127.0.0.1"
	}
	return baseScheme + "://" + net.JoinHostPort(host, port)
}

func openBrowser(rawurl string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", rawurl)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", rawurl)
	default:
		cmd = exec.Command("xdg-open", rawurl)
	}
	return cmd.Start()
}
