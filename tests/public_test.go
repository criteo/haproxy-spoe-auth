package tests

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShouldAccessPublicPageWithoutCredentials(t *testing.T) {
	req, err := http.NewRequest("GET", PublicURL, nil)
	assert.NoError(t, err)

	res, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)

	assert.Equal(t, 200, res.StatusCode)
}
