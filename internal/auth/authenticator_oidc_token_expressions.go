package auth

import (
	"errors"

	"github.com/tidwall/gjson"
)

// Lowercase is intentional to make it easier to write in HAProxy configuration
const (
	operationIn           string = "in"
	operationNotIn        string = "notin"
	operationExists       string = "exists"
	operationDoesNotExist string = "doesnotexist"
)

var ErrParseTokenExpressionRequest = errors.New("failed to parse OAuthTokenExpression")

type OAuthTokenExpressionOperation int

func (te OAuthTokenExpressionOperation) String() string {
	switch te {
	case in:
		return operationIn
	case notIn:
		return operationNotIn
	case exists:
		return operationExists
	case doesNotExist:
		return operationDoesNotExist
	}

	return ""
}

const (
	in OAuthTokenExpressionOperation = iota + 1
	notIn
	exists
	doesNotExist
)

type OAuthTokenExpression struct {
	TokenClaim string
	RawValue   string
	Operation  OAuthTokenExpressionOperation
}

func existsIn(tokenValue *gjson.Result, lookupVal string) bool {
	if !tokenValue.IsArray() {
		return false
	}

	var found bool

	tokenValue.ForEach(func(_, value gjson.Result) bool {
		if value.String() == lookupVal {
			found = true
			return false
		}

		return true
	})

	return found
}
