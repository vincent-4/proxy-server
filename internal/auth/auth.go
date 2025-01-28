package auth

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)


var ErrInvalidAuth = fmt.Errorf("invalid authentication")


type Config struct {
	Username string
	Password string
}


type Authenticator struct {
	config Config
}


func New(cfg Config) *Authenticator {
	return &Authenticator{
		config: cfg,
	}
}



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

	
	usernameMatch := subtle.ConstantTimeCompare([]byte(username), []byte(a.config.Username)) == 1
	passwordMatch := subtle.ConstantTimeCompare([]byte(password), []byte(a.config.Password)) == 1

	if !usernameMatch || !passwordMatch {
		return fmt.Errorf("%w: invalid credentials", ErrInvalidAuth)
	}

	return nil
}


func (a *Authenticator) RequireAuth(w http.ResponseWriter) {
	w.Header().Set("Proxy-Authenticate", "Basic realm=\"Proxy\"")
	http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
}
