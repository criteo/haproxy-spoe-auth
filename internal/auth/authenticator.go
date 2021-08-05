package auth

import spoe "github.com/criteo/haproxy-spoe-go"

// Authenticator the authenticator interface that can be implemented for LDAP, OAuth2, OIDC or whatever else.
type Authenticator interface {
	// Check whether the user is authenticated by this authenticator
	Authenticate(msg *spoe.Message) (bool, []spoe.Action, error)
}
