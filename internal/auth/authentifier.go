package auth

import spoe "github.com/criteo/haproxy-spoe-go"

// Authentifiter the authentifier interface that can be implemented for LDAP, OAuth2, OIDC or whatever else.
type Authentifiter interface {
	Authenticate(msg *spoe.Message) error
}
