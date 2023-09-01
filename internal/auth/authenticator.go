package auth

import (
	action "github.com/negasus/haproxy-spoe-go/action"
	message "github.com/negasus/haproxy-spoe-go/message"
)

// Authenticator the authenticator interface that can be implemented for LDAP, OAuth2, OIDC or whatever else.
type Authenticator interface {
	// Check whether the user is authenticated by this authenticator
	Authenticate(msg *message.Message) (bool, []action.Action, error)
}
