package auth

import spoe "github.com/criteo/haproxy-spoe-go"

// BuildRedirectURLMessage build a message containing the URL the user should be redirected too
func BuildRedirectURLMessage(url string) spoe.ActionSetVar {
	return spoe.ActionSetVar{
		Name:  "redirect_url",
		Scope: spoe.VarScopeSession,
		Value: url,
	}
}

// BuildHasErrorMessage build a message stating an error was thrown in SPOE agent
func BuildHasErrorMessage() spoe.ActionSetVar {
	return spoe.ActionSetVar{
		Name:  "has_error",
		Scope: spoe.VarScopeSession,
		Value: true,
	}
}
