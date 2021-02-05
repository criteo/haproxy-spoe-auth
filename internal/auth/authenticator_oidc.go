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
	ProviderURL  string
	ClientID     string
	ClientSecret string
	RedirectURL  string

	SignatureSecret string
	CookieName      string
	CookieDomain    string

	// The addr interface the callback will be exposed on.
	CallbackAddr string
}

// OIDCAuthenticator is the OIDC implementation of the Authenticator interface
type OIDCAuthenticator struct {
	config   oauth2.Config
	verifier *oidc.IDTokenVerifier
	provider *oidc.Provider

	signatureComputer *HmacSha256Computer

	options OIDCAuthenticatorOptions
}

// State the content of the state
type State struct {
	URL       string `json:"url"`
	Signature string `json:"sig"`
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
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
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
	}

	go func() {
		http.HandleFunc("/oauth2/callback", oa.handleOAuth2Callback(tmpl, errorTmpl))
		http.HandleFunc("/logout", oa.handleOAuth2Logout())
		http.ListenAndServe(options.CallbackAddr, nil)
	}()

	return oa
}

func extractArgs(msg *spoe.Message) (string, string, error) {
	var ssl *bool
	var host, pathq *string
	var cookie string

	for msg.Args.Next() {
		arg := msg.Args.Arg

		if arg.Name == "arg_ssl" {
			x, ok := arg.Value.(bool)
			if !ok {
				return "", "", fmt.Errorf("SSL is not a bool: %v", arg.Value)
			}

			ssl = new(bool)
			*ssl = x
			continue
		}

		if arg.Name == "arg_host" {
			x, ok := arg.Value.(string)
			if !ok {
				return "", "", fmt.Errorf("Host is not a string: %v", arg.Value)
			}

			host = new(string)
			*host = x
			continue
		}

		if arg.Name == "arg_pathq" {
			x, ok := arg.Value.(string)
			if !ok {
				return "", "", fmt.Errorf("Pathq is not a string: %v", arg.Value)
			}

			pathq = new(string)
			*pathq = x
			continue
		}

		if arg.Name == "arg_cookie" {
			x, ok := arg.Value.(string)
			if !ok {
				continue
			}

			cookie = x
			continue
		}
	}

	if ssl == nil {
		return "", "", fmt.Errorf("SSL arg not found")
	}

	if host == nil {
		return "", "", fmt.Errorf("Host arg not found")
	}

	if pathq == nil {
		return "", "", fmt.Errorf("Pathq arg not found")
	}

	scheme := "http"
	if *ssl {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s%s", scheme, *host, *pathq), cookie, nil
}

// Authenticate treat an authentication request coming from HAProxy
func (oa *OIDCAuthenticator) Authenticate(msg *spoe.Message) ([]spoe.Action, error) {
	originURL, cookie, err := extractArgs(msg)
	if err != nil {
		return nil, fmt.Errorf("Unable to extract origin URL: %v", err)
	}

	// Verify the cookie to make sure the user is authenticated
	if cookie == "test1" {
		logrus.Debug("User is already authenticated")
		return []spoe.Action{AuthenticatedMessage}, nil
	}

	var state State
	state.URL = originURL
	state.Signature = oa.signatureComputer.ProduceSignature(originURL)

	stateBytes, err := json.Marshal(state)
	if err != nil {
		return []spoe.Action{NotAuthenticatedMessage}, fmt.Errorf("Unable to marshal the state")
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

		// Extract custom claims
		var claims struct {
			Email    string `json:"email"`
			Verified bool   `json:"email_verified"`
		}
		if err := idToken.Claims(&claims); err != nil {
			// handle error
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

		ttl := 60 * time.Second
		expire := time.Now().Add(ttl)
		cookie := http.Cookie{
			Name:     oa.options.CookieName,
			Value:    "test1",
			Path:     "/",
			Expires:  expire,
			Domain:   oa.options.CookieDomain,
			HttpOnly: true,
		}

		http.SetCookie(w, &cookie)

		err = tmpl.Execute(w, struct{ URL string }{URL: string(state.URL)})
		if err != nil {
			logrus.Errorf("Unable to render redirect template: %v", err)
			http.Error(w, "Bad request", http.StatusBadRequest)
		}
	}
}

// RedirectPage is a template used for the final redirection
var RedirectPage = `
<head>
<title>Redirection in progress</title>
  <meta http-equiv="refresh" content="0; URL={{.URL}}" />
</head>
<body>
</body>`

// ErrorPage is a template used in the case the final redirection cannot happen due to the bad signature of the original URL
var ErrorPage = `
<head>
  <title>Error on redirection</title>
</head>
<body>
You cannot be redirected to this untrusted url {{.URL}}.
</body>`

// LogoutPage is an HTML content stating the user has been logged out successfully
var LogoutPage = `
<head>
<title>Logout</title>
</head>
<body>
You have been logged out successfully.
</body>`
