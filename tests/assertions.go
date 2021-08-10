package tests

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tebeka/selenium"
)

// WaitUntilBodyContains wait until the body of the page contains match
func (ewd *ExtendedWebDriver) WaitUntilBodyContains(ctx context.Context, t *testing.T, match string) {
	err := ewd.Wait(ctx, func(driver selenium.WebDriver) (bool, error) {
		body, err := driver.FindElement(selenium.ByTagName, "body")

		if err != nil {
			return false, fmt.Errorf("unable to get current URL: %v", err)
		}
		bodyContent, err := body.Text()
		if err != nil {
			return false, fmt.Errorf("unable to retrieve body: %v", err)
		}
		return strings.Contains(bodyContent, match), nil
	})

	require.NoError(t, err)
}

// WaitUntilURLIs wait until the URL in the browser bar is the expected one
func (ewd *ExtendedWebDriver) WaitUntilURLIs(ctx context.Context, t *testing.T, url string) {
	err := ewd.Wait(ctx, func(driver selenium.WebDriver) (bool, error) {
		currentURL, err := driver.CurrentURL()

		if err != nil {
			return false, fmt.Errorf("unable to get current URL: %v", err)
		}
		return currentURL == url, nil
	})

	require.NoError(t, err)
}

// WaitUntilURLStartsWith wait until the client is redirected to an url starting with a given prefix
func (ewd *ExtendedWebDriver) WaitUntilURLStartsWith(ctx context.Context, t *testing.T, prefix string) {
	err := ewd.Wait(ctx, func(driver selenium.WebDriver) (bool, error) {
		currentURL, err := driver.CurrentURL()

		if err != nil {
			return false, fmt.Errorf("unable to get current URL: %v", err)
		}

		return strings.HasPrefix(currentURL, prefix), nil
	})

	require.NoError(t, err)
}

// WaitUntilRedirectedToDexLogin wait until the client is redirected to dex login portal
func (ewd *ExtendedWebDriver) WaitUntilRedirectedToDexLogin(ctx context.Context, t *testing.T) {
	ewd.WaitUntilURLStartsWith(ctx, t, "http://dex.example.com:9080/dex/auth/ldap?req=")
}

// WaitUntilRedirectedToDexApproval wait until the client is redirected to dex approval page
func (ewd *ExtendedWebDriver) WaitUntilRedirectedToDexApproval(ctx context.Context, t *testing.T) {
	ewd.WaitUntilURLStartsWith(ctx, t, "http://dex.example.com:9080/dex/approval?req=")
}

// WaitUntilDexCredentialsFieldsAreDetetected wait until the credential fields in the dex UI are located
func (ewd *ExtendedWebDriver) WaitUntilDexCredentialsFieldsAreDetetected(ctx context.Context, t *testing.T) {
	ewd.WaitElementLocatedByID(ctx, t, "login")
	ewd.WaitElementLocatedByID(ctx, t, "password")
}

// WaitUntilAuthenticatedWithOIDC wait until the authentication workflow has been executed.
// This assert goes from the redirection to dex up to the click on the button to grant access to the information
func (ewd *ExtendedWebDriver) WaitUntilAuthenticatedWithOIDC(ctx context.Context, t *testing.T, username, password string) {
	ewd.WaitUntilRedirectedToDexLogin(ctx, t)
	ewd.WaitUntilDexCredentialsFieldsAreDetetected(ctx, t)
	ewd.FillCredentials(ctx, t, username, password)
	ewd.WaitUntilRedirectedToDexApproval(ctx, t)
	ewd.ClickOnGrantAccess(ctx, t)
}

// WaitUntilLoginErrorAppear wait until the error message in dex appears.
func (ewd *ExtendedWebDriver) WaitUntilLoginErrorAppear(ctx context.Context, t *testing.T) {
	loginError := ewd.WaitElementLocatedByID(ctx, t, "login-error")
	assert.NotNil(t, loginError)
}
