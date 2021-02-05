package tests

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestShouldAuthenticateSuccessfully(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	assert.NoError(t, WithWebdriver(func(wd ExtendedWebDriver) error {
		wd.Get(ProtectedOidcURL)
		wd.WaitUntilAuthenticatedWithOIDC(ctx, t, "john", "password")
		wd.WaitUntilURLIs(ctx, t, "http://protected-oidc.example.com:9080/")
		wd.WaitUntilBodyContains(ctx, t, "PROTECTED!")
		return nil
	}))
}

func TestShouldKeepUseLoggedIn(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	assert.NoError(t, WithWebdriver(func(wd ExtendedWebDriver) error {
		wd.Get(ProtectedOidcURL)
		wd.WaitUntilAuthenticatedWithOIDC(ctx, t, "john", "password")
		wd.WaitUntilURLIs(ctx, t, ProtectedOidcURL)
		wd.WaitUntilBodyContains(ctx, t, "PROTECTED!")
		wd.Get(UnprotectedURL)
		wd.WaitUntilURLIs(ctx, t, UnprotectedURL)
		wd.WaitUntilBodyContains(ctx, t, "Public!")
		// Cookie should be sent and access should be given directly
		wd.Get(ProtectedOidcURL)
		wd.WaitUntilURLIs(ctx, t, ProtectedOidcURL)
		wd.WaitUntilBodyContains(ctx, t, "PROTECTED!")
		return nil
	}))
}

func TestShouldFailAuthentication(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	assert.NoError(t, WithWebdriver(func(wd ExtendedWebDriver) error {
		wd.Get(ProtectedOidcURL)
		wd.WaitUntilRedirectedToDexLogin(ctx, t)
		wd.WaitUntilDexCredentialsFieldsAreDetetected(ctx, t)
		wd.FillCredentials(ctx, t, "john", "badpassword")
		wd.WaitUntilLoginErrorAppear(ctx, t)
		return nil
	}))
}
