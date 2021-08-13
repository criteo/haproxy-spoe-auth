package tests

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShouldAuthenticateSuccessfullyInLDAP(t *testing.T) {
	req, err := http.NewRequest("GET", App1URL, nil)
	assert.NoError(t, err)
	req.SetBasicAuth("john", "password")

	res, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)

	assert.Equal(t, 200, res.StatusCode)
}

func TestShouldFailAuthenticationInLDAP(t *testing.T) {
	req, err := http.NewRequest("GET", App1URL, nil)
	assert.NoError(t, err)
	req.SetBasicAuth("john", "badpassword")

	res, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)

	assert.Equal(t, 401, res.StatusCode)
}

func TestShouldFailWhenNoCredsProvided(t *testing.T) {
	req, err := http.NewRequest("GET", App1URL, nil)
	assert.NoError(t, err)

	res, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)

	assert.Equal(t, 401, res.StatusCode)
}
