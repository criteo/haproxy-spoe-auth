package auth

import action "github.com/negasus/haproxy-spoe-go/action"

// BuildRedirectURLMessage build a message containing the URL the user should be redirected too
func BuildRedirectURLMessage(url string) action.Action {
	return action.NewSetVar(action.ScopeSession, "redirect_url", url)
}

// BuildHasErrorMessage build a message stating an error was thrown in SPOE agent
func BuildHasErrorMessage() action.Action {
	return action.NewSetVar(action.ScopeSession, "has_error", true)
}

// AuthenticatedUserMessage build a message containing the username of the authenticated user
func AuthenticatedUserMessage(username string) action.Action {
	return action.NewSetVar(action.ScopeSession, "authenticated_user", username)
}
