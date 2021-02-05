package tests

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tebeka/selenium"
)

// FillCredentials wait until the credential fields in the dex UI are located
func (ewd *ExtendedWebDriver) FillCredentials(ctx context.Context, t *testing.T, username, password string) {
	loginEl := ewd.WaitElementLocatedByID(ctx, t, "login")
	passwordEl := ewd.WaitElementLocatedByID(ctx, t, "password")

	submitEl := ewd.WaitElementLocatedByID(ctx, t, "submit-login")

	loginEl.SendKeys(username)
	passwordEl.SendKeys(password)
	submitEl.Click()
}

// ClickOnGrantAccess click on the grant access button in the dex approval page
func (ewd *ExtendedWebDriver) ClickOnGrantAccess(ctx context.Context, t *testing.T) {
	formsEl := ewd.WaitElementsLocatedByTagName(ctx, t, "form")
	assert.Len(t, formsEl, 2)
	buttonEl, err := formsEl[0].FindElement(selenium.ByTagName, "button")
	assert.NoError(t, err)
	buttonEl.Click()
}
