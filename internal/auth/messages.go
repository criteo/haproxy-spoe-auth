package auth

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

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

func BuildTokenClaimsMessage(claimsVals *gjson.Result, claimsFilter []string) []action.Action {
	result := make([]action.Action, 0, len(claimsFilter))

	for i := range claimsFilter {
		value := claimsVals.Get(claimsFilter[i])

		if !value.Exists() {
			continue
		}

		key := computeSPOEClaimKey(claimsFilter[i])
		result = append(result, action.NewSetVar(action.ScopeSession, key, gjsonToSPOEValue(&value)))
	}

	return result
}

// The obvious constants are defined here so as not to have "magic" numbers
// in HAProxy SPOE response actions.
const (
	valueTrue  = 1
	valueFalse = 0
)

var ErrTokenExpressionUnknownOperation = errors.New("unknown operation is provided as token expression")

func EvaluateTokenExpressions(claimsVals *gjson.Result, tokenExpressions []OAuthTokenExpression) ([]action.Action, error) {
	var result = make([]action.Action, 0, len(tokenExpressions))

	for i := range tokenExpressions {
		pe := &tokenExpressions[i]

		value := claimsVals.Get(pe.TokenClaim)

		switch pe.Operation {
		case in:
			if existsIn(&value, pe.RawValue) {
				result = append(
					result,
					action.NewSetVar(action.ScopeSession, computeSPOEExpressionKey(pe), valueTrue))

			} else {
				result = append(
					result,
					action.NewSetVar(action.ScopeSession, computeSPOEExpressionKey(pe), valueFalse))
			}

		case notIn:
			if !existsIn(&value, pe.RawValue) {
				result = append(
					result,
					action.NewSetVar(action.ScopeSession, computeSPOEExpressionKey(pe), valueTrue))

			} else {
				result = append(
					result,
					action.NewSetVar(action.ScopeSession, computeSPOEExpressionKey(pe), valueFalse))
			}

		case exists:
			if value.Exists() {
				result = append(
					result,
					action.NewSetVar(action.ScopeSession, computeSPOEExpressionKey(pe), valueTrue))
			} else {
				result = append(
					result,
					action.NewSetVar(action.ScopeSession, computeSPOEExpressionKey(pe), valueFalse))
			}

		case doesNotExist:
			if value.Exists() {
				result = append(
					result,
					action.NewSetVar(action.ScopeSession, computeSPOEExpressionKey(pe), valueFalse))
			} else {
				result = append(
					result,
					action.NewSetVar(action.ScopeSession, computeSPOEExpressionKey(pe), valueTrue))
			}

		default:
			return nil, fmt.Errorf("%w: token expression: +%v", ErrTokenExpressionUnknownOperation, *pe)
		}
	}

	return result, nil
}

func normalizeSPOEKV(s string) string {
	var result = &strings.Builder{}

	result.Grow(len(s))

	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			_, _ = result.WriteRune(c)
		} else {
			_, _ = result.WriteRune('_')
		}
	}

	return result.String()
}

func computeSPOEClaimKey(key string) string {
	return "token_claim_" + normalizeSPOEKV(key)
}

func normalizeSPOEExpressionValue(val string) string {
	return normalizeSPOEKV(val)
}

func decodeRequestValue(s string) (string, error) {
	val, err := url.QueryUnescape(s)
	if err != nil {
		return "", err
	}

	return val, nil
}

func computeSPOEExpressionKey(expr *OAuthTokenExpression) string {
	var result = &strings.Builder{}

	_, _ = result.WriteString("token_expression_")
	_, _ = result.WriteString(expr.Operation.String())
	_, _ = result.WriteRune('_')
	_, _ = result.WriteString(normalizeSPOEKV(expr.TokenClaim))

	if expr.Operation == exists || expr.Operation == doesNotExist {
		return result.String()
	}

	_, _ = result.WriteRune('_')

	_, _ = result.WriteString(normalizeSPOEExpressionValue(expr.RawValue))

	return result.String()
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
