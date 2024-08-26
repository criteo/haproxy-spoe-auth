package auth

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type TestParseTokenExpressionsSuite struct {
	suite.Suite
}

func (s *TestParseTokenExpressionsSuite) TestParseSuccess() {
	type testCase struct {
		argument string
		expected []OAuthTokenExpression
	}

	var tests []testCase = []testCase{
		{
			argument: "in;roles;IT%20Team in;roles;Accountants in;roles;Electrical%20Engineers",
			expected: []OAuthTokenExpression{
				{
					TokenClaim: "roles",
					RawValue:   "IT Team",
					Operation:  in,
				},
				{
					TokenClaim: "roles",
					RawValue:   "Accountants",
					Operation:  in,
				},
				{
					TokenClaim: "roles",
					RawValue:   "Electrical Engineers",
					Operation:  in,
				},
			},
		},
	}

	for _, t := range tests {
		result, err := parseTokenExpressions(t.argument)

		s.NoError(err, "Must not fail")
		s.Equal(t.expected, result, "Unexpected parsed result")
	}

}

func TestParseTokenExpressions(t *testing.T) {
	suite.Run(t, &TestParseTokenExpressionsSuite{})
}
