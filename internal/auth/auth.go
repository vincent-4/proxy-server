package auth

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

// ErrInvalidAuth represents an authentication error
var ErrInvalidAuth = fmt.Errorf("invalid authentication")

// Config holds authentication configuration
type Config struct {
	Username string
	Password string
}

// Authenticator handles basic authentication for the proxy server
type Authenticator struct {
	config Config
}

// New creates a new Authenticator instance
func New(cfg Config) *Authenticator {
	return &Authenticator{
		config: cfg,
	}
}

// Authenticate checks if the request has valid basic auth credentials.
// It returns an error if authentication fails.
func (a *Authenticator) Authenticate(r *http.Request) error {
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		return fmt.Errorf("%w: no credentials provided", ErrInvalidAuth)
	}

	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return fmt.Errorf("%w: invalid auth type", ErrInvalidAuth)
	}

	decoded, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return fmt.Errorf("%w: invalid base64 encoding", ErrInvalidAuth)
	}

	credentials := strings.SplitN(string(decoded), ":", 2)
	if len(credentials) != 2 {
		return fmt.Errorf("%w: invalid credential format", ErrInvalidAuth)
	}

	username, password := credentials[0], credentials[1]

	// Use constant time comparison to prevent timing attacks
	usernameMatch := subtle.ConstantTimeCompare([]byte(username), []byte(a.config.Username)) == 1
	passwordMatch := subtle.ConstantTimeCompare([]byte(password), []byte(a.config.Password)) == 1

	if !usernameMatch || !passwordMatch {
		return fmt.Errorf("%w: invalid credentials", ErrInvalidAuth)
	}

	return nil
}

// RequireAuth adds the Proxy-Authenticate header to the response
func (a *Authenticator) RequireAuth(w http.ResponseWriter) {
	w.Header().Set("Proxy-Authenticate", "Basic realm=\"Proxy\"")
	http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
}
