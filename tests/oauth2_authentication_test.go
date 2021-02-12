package tests

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestOAuth2ShouldAuthenticateSuccessfully(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	assert.NoError(t, WithWebdriver(func(wd ExtendedWebDriver) error {
		wd.Get(ProtectedOAuth2URL)
		wd.WaitUntilAuthenticatedWithOIDC(ctx, t, "john", "password")
		wd.WaitUntilURLIs(ctx, t, "http://protected-oauth2.example.com:9080/")
		wd.WaitUntilBodyContains(ctx, t, "PROTECTED!")
		return nil
	}))
}

func TestOAuth2ShouldKeepUseLoggedIn(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	assert.NoError(t, WithWebdriver(func(wd ExtendedWebDriver) error {
		wd.Get(ProtectedOAuth2URL)
		wd.WaitUntilAuthenticatedWithOIDC(ctx, t, "john", "password")
		wd.WaitUntilURLIs(ctx, t, ProtectedOAuth2URL)
		wd.WaitUntilBodyContains(ctx, t, "PROTECTED!")
		wd.Get(UnprotectedURL)
		wd.WaitUntilURLIs(ctx, t, UnprotectedURL)
		wd.WaitUntilBodyContains(ctx, t, "Public!")
		// Cookie should be sent and access should be given directly
		wd.Get(ProtectedOAuth2URL)
		wd.WaitUntilURLIs(ctx, t, ProtectedOAuth2URL)
		wd.WaitUntilBodyContains(ctx, t, "PROTECTED!")
		return nil
	}))
}

func TestOAuth2ShouldFailAuthentication(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	assert.NoError(t, WithWebdriver(func(wd ExtendedWebDriver) error {
		wd.Get(ProtectedOAuth2URL)
		wd.WaitUntilRedirectedToDexLogin(ctx, t)
		wd.WaitUntilDexCredentialsFieldsAreDetetected(ctx, t)
		wd.FillCredentials(ctx, t, "john", "badpassword")
		wd.WaitUntilLoginErrorAppear(ctx, t)
		return nil
	}))
}
