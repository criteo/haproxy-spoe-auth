package tests

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnprotectedEndpoint(t *testing.T) {
	url := "http://unprotected.example.com:9080/"
	resp, err := http.Get(url)

	assert.NoError(t, err)
	assert.Equal(t, resp.StatusCode, 200, "Status code should be 200")
}

func TestProtectedEndpointWithoutAuthentication(t *testing.T) {
	url := "http://protected.example.com:9080/"
	resp, err := http.Get(url)

	assert.NoError(t, err)
	assert.Equal(t, resp.StatusCode, 401, "Status code should be 401")
}

func TestProtectedEndpointWithFailedAuthentication(t *testing.T) {
	url := "http://protected.example.com:9080/"
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	req.SetBasicAuth("john", "badpassword")
	resp, err := client.Do(req)

	assert.NoError(t, err)
	assert.Equal(t, resp.StatusCode, 401, "Status code should be 401")
}

func TestProtectedEndpointWithSuccessfulAuthentication(t *testing.T) {
	url := "http://protected.example.com:9080/"
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	req.SetBasicAuth("john", "password")
	resp, err := client.Do(req)

	assert.NoError(t, err)
	assert.Equal(t, resp.StatusCode, 200, "Status code should be 401")
}
