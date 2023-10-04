package auth

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	action "github.com/negasus/haproxy-spoe-go/action"
	"github.com/tidwall/gjson"
)

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

func BuildTokenClaimsMessage(idToken *oidc.IDToken, claimsFilter []string) ([]action.Action, error) {
	var claimsData json.RawMessage

	if err := idToken.Claims(&claimsData); err != nil {
		return nil, fmt.Errorf("unable to load OIDC claims: %w", err)
	}

	claimsVals := gjson.ParseBytes(claimsData)
	result := make([]action.Action, 0, len(claimsFilter))

	for i := range claimsFilter {
		value := claimsVals.Get(claimsFilter[i])

		if !value.Exists() {
			continue
		}

		key := computeSPOEKey(claimsFilter[i])
		result = append(result, action.NewSetVar(action.ScopeSession, key, gjsonToSPOEValue(&value)))
	}

	return result, nil
}

var spoeKeyReplacer = strings.NewReplacer("-", "_", ".", "_")

func computeSPOEKey(key string) string {
	return "token_claim_" + spoeKeyReplacer.Replace(key)
}

func gjsonToSPOEValue(value *gjson.Result) interface{} {
	switch value.Type {
	case gjson.Null:
		// Null is a null json value
		return nil

	case gjson.Number:
		// Number is json number
		return value.Int()

	case gjson.String:
		// String is a json string
		return value.String()

	default:
		if value.IsArray() {
			// Make a comma separated list.
			tmp := value.Array()
			lastInd := len(tmp) - 1
			sb := &strings.Builder{}

			for i := 0; i <= lastInd; i++ {
				sb.WriteString(tmp[i].String())

				if i != lastInd {
					sb.WriteRune(',')
				}
			}

			return sb.String()
		}

		// Other types such as True, False, JSON.
		return value.String()
	}
}
