package tests

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestShouldAuthenticateSuccessfully(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	assert.NoError(t, WithWebdriver(func(wd ExtendedWebDriver) error {
		// In case the cookie is set, we logout the user before running the test.
		wd.Get(fmt.Sprintf("%soauth2/logout", App2URL))

		wd.Get(App2URL)
		wd.WaitUntilAuthenticatedWithOIDC(ctx, t, "john", "password")
		wd.WaitUntilURLIs(ctx, t, App2URL)
		wd.WaitUntilBodyContains(ctx, t, "PROTECTED!")
		return nil
	}))
}

func TestShouldVerifyUserRedirectedToInitialURL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	assert.NoError(t, WithWebdriver(func(wd ExtendedWebDriver) error {
		// In case the cookie is set, we logout the user before running the test.
		wd.Get(fmt.Sprintf("%soauth2/logout", App2URL))

		wd.Get(App2URL)
		wd.WaitUntilAuthenticatedWithOIDC(ctx, t, "john", "password")
		wd.WaitUntilURLIs(ctx, t, App2URL)
		wd.WaitUntilBodyContains(ctx, t, "PROTECTED!")
		url := fmt.Sprintf("%ssecret.html", App2URL)
		wd.Get(url)
		wd.WaitUntilURLIs(ctx, t, url)
		wd.WaitUntilBodyContains(ctx, t, "SECRET!")
		return nil
	}))
}

func TestShouldKeepUseLoggedIn(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	assert.NoError(t, WithWebdriver(func(wd ExtendedWebDriver) error {
		// In case the cookie is set, we logout the user before running the test.
		wd.Get(fmt.Sprintf("%soauth2/logout", App2URL))

		wd.Get(App2URL)
		wd.WaitUntilAuthenticatedWithOIDC(ctx, t, "john", "password")
		wd.WaitUntilURLIs(ctx, t, App2URL)
		wd.WaitUntilBodyContains(ctx, t, "PROTECTED!")
		wd.Get(PublicURL)
		wd.WaitUntilURLIs(ctx, t, PublicURL)
		wd.WaitUntilBodyContains(ctx, t, "Public!")
		// Cookie should be sent and access should be given directly
		wd.Get(App2URL)
		wd.WaitUntilURLIs(ctx, t, App2URL)
		wd.WaitUntilBodyContains(ctx, t, "PROTECTED!")
		return nil
	}))
}

func TestShouldFailAuthentication(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	assert.NoError(t, WithWebdriver(func(wd ExtendedWebDriver) error {
		// In case the cookie is set, we logout the user before running the test.
		wd.Get(fmt.Sprintf("%soauth2/logout", App2URL))

		wd.Get(App2URL)
		wd.WaitUntilRedirectedToDexLogin(ctx, t)
		wd.WaitUntilDexCredentialsFieldsAreDetetected(ctx, t)
		wd.FillCredentials(ctx, t, "john", "badpassword")
		wd.WaitUntilLoginErrorAppear(ctx, t)
		return nil
	}))
}
