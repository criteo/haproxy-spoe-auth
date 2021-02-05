package auth

import spoe "github.com/criteo/haproxy-spoe-go"

// NotAuthenticatedMessage SPOE response stating the user is not authenticated
var NotAuthenticatedMessage = spoe.ActionSetVar{
	Name:  "is_authenticated",
	Scope: spoe.VarScopeSession,
	Value: false,
}

// AuthenticatedMessage SPOE response stating the user is authenticated
var AuthenticatedMessage = spoe.ActionSetVar{
	Name:  "is_authenticated",
	Scope: spoe.VarScopeSession,
	Value: true,
}

// BuildRedirectURLMessage build a message containing the URL the user should be redirected too
func BuildRedirectURLMessage(url string) spoe.ActionSetVar {
	return spoe.ActionSetVar{
		Name:  "redirect_url",
		Scope: spoe.VarScopeSession,
		Value: url,
	}
}
