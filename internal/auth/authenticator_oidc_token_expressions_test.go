package auth

import (
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/tidwall/gjson"
)

type TestTokenExpressionsSuite struct {
	suite.Suite
}

func (s *TestTokenExpressionsSuite) TestExistsInPositive() {
	var (
		tokenValue = gjson.Parse(`[ "value1", "value2", "value3" ]`)
		lookupVal  = "value2"
	)

	result := existsIn(&tokenValue, lookupVal)

	s.Truef(result, "Token value: %s, lookup value: %s", tokenValue, lookupVal)
}

func (s *TestTokenExpressionsSuite) TestExistsInNegative() {
	var (
		tokenValue = gjson.Parse(`[ "value1", "value2", "value3" ]`)
		lookupVal  = "value5"
	)

	result := existsIn(&tokenValue, lookupVal)

	s.Falsef(result, "Token value: %s, lookup value: %s", tokenValue, lookupVal)
}

func (s *TestTokenExpressionsSuite) TestExistsInNotArray() {
	var (
		tokenValue = gjson.Parse(`{ "value1": "value2", "value3": "value4" }`)
		lookupVal  = "value2"
	)

	result := existsIn(&tokenValue, lookupVal)

	s.Falsef(result, "Token value: %s, lookup value: %s", tokenValue, lookupVal)
}

func (s *TestTokenExpressionsSuite) TestExistsInInvalidData() {
	var (
		tokenValue = gjson.Parse(`[ "value1" "value2" "value3" ]`)
		lookupVal  = "value2"
	)

	result := existsIn(&tokenValue, lookupVal)

	s.Truef(result, "Token value: %s, lookup value: %s", tokenValue, lookupVal)
}

func TestTokenExpressions(t *testing.T) {
	suite.Run(t, &TestTokenExpressionsSuite{})
}
