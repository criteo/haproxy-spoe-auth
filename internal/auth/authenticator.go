package auth

import spoe "github.com/criteo/haproxy-spoe-go"

// Authenticator the authenticator interface that can be implemented for LDAP, OAuth2, OIDC or whatever else.
type Authenticator interface {
	Authenticate(msg *spoe.Message) ([]spoe.Action, error)
}
