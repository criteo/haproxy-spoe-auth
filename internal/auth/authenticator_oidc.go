package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"text/template"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/coreos/go-oidc/v3/oidc"
	spoe "github.com/criteo/haproxy-spoe-go"
	"golang.org/x/oauth2"
)

// OIDCAuthenticatorOptions options to customize to the OIDC authenticator
type OIDCAuthenticatorOptions struct {
	OAuth2AuthenticatorOptions

	// The URL to the OIDC provider exposing the configuration
	ProviderURL string

	// This is used to encrypt the ID Token returned by the IdP.
	EncryptionSecret string
}

// OIDCAuthenticator is the OIDC implementation of the Authenticator interface
type OIDCAuthenticator struct {
	config   oauth2.Config
	verifier *oidc.IDTokenVerifier
	provider *oidc.Provider

	signatureComputer *HmacSha256Computer
	encryptor         *AESEncryptor

	options OIDCAuthenticatorOptions
}

// NewOIDCAuthenticator create an instance of an OIDC authenticator
func NewOIDCAuthenticator(options OIDCAuthenticatorOptions) *OIDCAuthenticator {
	if len(options.SignatureSecret) < 16 {
		logrus.Fatalf("The signature secret should be at least 16 characters, %d provided", len(options.SignatureSecret))
	}

	provider, err := oidc.NewProvider(context.Background(), options.ProviderURL)
	if err != nil {
		logrus.Fatalf("Unable to create OIDC provider structure: %v", err)
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: options.ClientID})

	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := oauth2.Config{
		ClientID:     options.ClientID,
		ClientSecret: options.ClientSecret,
		RedirectURL:  options.RedirectURL,

		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "email", "profile"},
	}

	tmpl, err := template.New("redirect_html").Parse(RedirectPage)
	if err != nil {
		logrus.Fatalf("Unable to read the html page for redirecting")
	}

	errorTmpl, err := template.New("error").Parse(ErrorPage)
	if err != nil {
		logrus.Fatalf("Unable to read the html page for redirecting")
	}

	oa := &OIDCAuthenticator{
		config:            oauth2Config,
		verifier:          verifier,
		provider:          provider,
		options:           options,
		signatureComputer: NewHmacSha256Computer(options.SignatureSecret),
		encryptor:         NewAESEncryptor(options.EncryptionSecret),
	}

	go func() {
		http.HandleFunc("/oauth2/callback", oa.handleOAuth2Callback(tmpl, errorTmpl))
		http.HandleFunc("/logout", oa.handleOAuth2Logout())
		http.ListenAndServe(options.CallbackAddr, nil)
	}()

	return oa
}

func (oa *OIDCAuthenticator) checkCookie(cookieValue string) error {
	idToken, err := oa.encryptor.Decrypt(cookieValue)
	if err != nil {
		return fmt.Errorf("unable to decrypt session cookie: %v", err)
	}

	// Parse and verify ID Token payload.
	_, err = oa.verifier.Verify(context.Background(), idToken)
	if err != nil {
		return fmt.Errorf("unable to verify ID Token: %v", err)
	}
	return nil
}

// Authenticate treat an authentication request coming from HAProxy
func (oa *OIDCAuthenticator) Authenticate(msg *spoe.Message) ([]spoe.Action, error) {
	originURL, cookieValue, err := extractOAuth2Args(msg)
	if err != nil {
		return nil, fmt.Errorf("unable to extract origin URL: %v", err)
	}

	// Verify the cookie to make sure the user is authenticated
	if cookieValue != "" {
		err := oa.checkCookie(cookieValue)
		if err != nil {
			logrus.Debugf("Unable to verify cookie: %v", err)
		} else {
			return []spoe.Action{AuthenticatedMessage}, nil
		}
	}

	var state State
	state.URL = originURL
	state.Signature = oa.signatureComputer.ProduceSignature(originURL)

	stateBytes, err := json.Marshal(state)
	if err != nil {
		return []spoe.Action{NotAuthenticatedMessage}, fmt.Errorf("unable to marshal the state")
	}

	authorizationURL := oa.config.AuthCodeURL(base64.StdEncoding.EncodeToString(stateBytes))
	return []spoe.Action{NotAuthenticatedMessage, BuildRedirectURLMessage(authorizationURL)}, nil
}

func (oa *OIDCAuthenticator) handleOAuth2Logout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := http.Cookie{
			Name:     oa.options.CookieName,
			Path:     "/",
			Domain:   oa.options.CookieDomain,
			HttpOnly: true,
			Secure:   oa.options.CookieSecure,
		}
		http.SetCookie(w, &c)
		fmt.Fprint(w, LogoutPage)
	}
}

func (oa *OIDCAuthenticator) handleOAuth2Callback(tmpl *template.Template, errorTmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Verify state and errors.
		stateB64Payload := r.URL.Query().Get("state")
		if stateB64Payload == "" {
			http.Error(w, "Cannot extract the state", http.StatusBadRequest)
		}

		oauth2Token, err := oa.config.Exchange(r.Context(), r.URL.Query().Get("code"))
		if err != nil {
			logrus.Errorf("Unable to retrieve OAuth2 token: %v", err)
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		// Extract the ID Token from OAuth2 token.
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			logrus.Errorf("Unable to extract the raw id_token: %v", err)
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		// Parse and verify ID Token payload.
		idToken, err := oa.verifier.Verify(r.Context(), rawIDToken)
		if err != nil {
			logrus.Errorf("Unable to verify the ID token: %v", err)
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		stateJSONPayload, err := base64.StdEncoding.DecodeString(stateB64Payload)
		if err != nil {
			logrus.Errorf("Unable to decode origin URL from state: %v", err)
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		var state State
		err = json.Unmarshal(stateJSONPayload, &state)
		if err != nil {
			logrus.Errorf("Unable to unmarshal the state payload: %v", err)
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		signatureOk := oa.signatureComputer.VerifySignature(state.URL, state.Signature)
		if !signatureOk {
			err = errorTmpl.Execute(w, struct{ URL string }{URL: string(state.URL)})
			if err != nil {
				logrus.Errorf("Unable to render error template: %v", err)
				http.Error(w, "Bad request", http.StatusBadRequest)
				return
			}
			return
		}

		encryptedIDToken, err := oa.encryptor.Encrypt(rawIDToken)

		if err != nil {
			logrus.Errorf("Unable to encrypt the ID token: %v", err)
			http.Error(w, "Bad request", http.StatusBadRequest)
		}

		var expiry time.Time
		if oa.options.CookieTTL == 0 {
			// Align the expiry of the session to the expiry of the ID Token if the options has not been set.
			expiry = idToken.Expiry
		} else { // otherwise take the value in seconds provided as argument
			expiry = time.Now().Add(oa.options.CookieTTL)
		}

		cookie := http.Cookie{
			Name:     oa.options.CookieName,
			Value:    encryptedIDToken,
			Path:     "/",
			Expires:  expiry,
			Domain:   oa.options.CookieDomain,
			HttpOnly: true,
			Secure:   oa.options.CookieSecure,
		}

		http.SetCookie(w, &cookie)

		err = tmpl.Execute(w, struct{ URL string }{URL: string(state.URL)})
		if err != nil {
			logrus.Errorf("Unable to render redirect template: %v", err)
			http.Error(w, "Bad request", http.StatusBadRequest)
		}
	}
}
