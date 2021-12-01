package auth

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/http"
	"strings"
	"text/template"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vmihailenco/msgpack/v5"

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

// OAuth2AuthenticatorOptions options to customize to the OAuth2 authenticator
type OAuth2AuthenticatorOptions struct {
	Endpoints            oauth2.Endpoint
	RedirectCallbackPath string
	LogoutPath           string
	HealthCheckPath      string

	// This is used to sign the redirection URL
	SignatureSecret string

	CookieName   string
	CookieSecure bool
	CookieTTL    time.Duration

	// The addr interface the callback will be exposed on.
	CallbackAddr string

	// The object retrieving the OIDC client configuration from the given domain
	ClientsStore OIDCClientsStore
}

// State the content of the state
type State struct {
	Timestamp          time.Time
	Signature          string
	PathAndQueryString string
	SSL                bool
}

// OIDCAuthenticator is the OIDC implementation of the Authenticator interface
type OIDCAuthenticator struct {
	provider *oidc.Provider

	signatureComputer *HmacSha256Computer
	encryptor         *AESEncryptor

	options OIDCAuthenticatorOptions
}

// NewOIDCAuthenticator create an instance of an OIDC authenticator
func NewOIDCAuthenticator(options OIDCAuthenticatorOptions) *OIDCAuthenticator {
	if len(options.SignatureSecret) < 16 {
		logrus.Fatalf("the signature secret should be at least 16 characters, %d provided", len(options.SignatureSecret))
	}

	if options.OAuth2AuthenticatorOptions.ClientsStore == nil {
		logrus.Fatal("no client secret provided")
	}

	provider, err := oidc.NewProvider(context.Background(), options.ProviderURL)
	if err != nil {
		logrus.Fatalf("unable to create OIDC provider structure: %v", err)
	}

	tmpl, err := template.New("redirect_html").Parse(RedirectPageTemplate)
	if err != nil {
		logrus.Fatalf("unable to read the html page for redirecting")
	}

	errorTmpl, err := template.New("error").Parse(ErrorPageTemplate)
	if err != nil {
		logrus.Fatalf("unable to read the html page for redirecting")
	}

	oa := &OIDCAuthenticator{
		provider:          provider,
		options:           options,
		signatureComputer: NewHmacSha256Computer(options.SignatureSecret),
		encryptor:         NewAESEncryptor(options.EncryptionSecret),
	}

	go func() {
		http.HandleFunc(options.RedirectCallbackPath, oa.handleOAuth2Callback(tmpl, errorTmpl))
		http.HandleFunc(options.LogoutPath, oa.handleOAuth2Logout())
		http.HandleFunc(options.HealthCheckPath, handleHealthCheck)
		http.ListenAndServe(options.CallbackAddr, nil)
	}()

	return oa
}

func handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("OK"))
}

func (oa *OIDCAuthenticator) withOAuth2Config(domain string, callback func(c oauth2.Config) error) error {
	clientConfig, err := oa.options.ClientsStore.GetClient(domain)
	if err != nil {
		return fmt.Errorf("unable to find an oidc client for domain %s", domain)
	}
	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := oauth2.Config{
		ClientID:     clientConfig.ClientID,
		ClientSecret: clientConfig.ClientSecret,
		RedirectURL:  clientConfig.RedirectURL,

		// Discovery returns the OAuth2 endpoints.
		Endpoint: oa.provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "email", "profile"},
	}
	return callback(oauth2Config)
}

func (oa *OIDCAuthenticator) verifyIDToken(context context.Context, domain string, rawIDToken string) (*oidc.IDToken, error) {
	clientConfig, err := oa.options.ClientsStore.GetClient(domain)
	if err != nil {
		return nil, fmt.Errorf("unable to find an oidc client for domain %s", domain)
	}
	verifier := oa.provider.Verifier(&oidc.Config{ClientID: clientConfig.ClientID})

	// Parse and verify ID Token payload.
	idToken, err := verifier.Verify(context, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("unable to verify ID Token: %v", err)
	}
	return idToken, nil
}

func (oa *OIDCAuthenticator) checkCookie(cookieValue string, domain string) error {
	idToken, err := oa.encryptor.Decrypt(cookieValue)
	if err != nil {
		return fmt.Errorf("unable to decrypt session cookie: %v", err)
	}

	_, err = oa.verifyIDToken(context.Background(), domain, idToken)
	return err
}

func extractOAuth2Args(msg *spoe.Message) (bool, string, string, string, error) {
	var ssl *bool
	var host, pathq *string
	var cookie string

	for msg.Args.Next() {
		arg := msg.Args.Arg

		if arg.Name == "arg_ssl" {
			x, ok := arg.Value.(bool)
			if !ok {
				return false, "", "", "", fmt.Errorf("SSL is not a bool: %v", arg.Value)
			}

			ssl = new(bool)
			*ssl = x
			continue
		}

		if arg.Name == "arg_host" {
			x, ok := arg.Value.(string)
			if !ok {
				return false, "", "", "", fmt.Errorf("host is not a string: %v", arg.Value)
			}

			host = new(string)
			*host = x
			continue
		}

		if arg.Name == "arg_pathq" {
			x, ok := arg.Value.(string)
			if !ok {
				return false, "", "", "", fmt.Errorf("pathq is not a string: %v", arg.Value)
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
		return false, "", "", "", ErrSSLArgNotFound
	}

	if host == nil {
		return false, "", "", "", ErrHostArgNotFound
	}

	if pathq == nil {
		return false, "", "", "", ErrPathqArgNotFound
	}
	return *ssl, *host, *pathq, cookie, nil
}

func (oa *OIDCAuthenticator) computeStateSignature(state *State) string {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(state.Timestamp.Unix()))
	data := append(b, state.PathAndQueryString...)
	var ssl byte = 0
	if state.SSL {
		ssl = 1
	}
	data = append(data, ssl)
	return oa.signatureComputer.ProduceSignature(data)
}

func extractDomainFromHost(host string) string {
	l := strings.Split(host, ":")
	if len(l) < 1 {
		return ""
	}
	return l[0]
}

// Authenticate treat an authentication request coming from HAProxy
func (oa *OIDCAuthenticator) Authenticate(msg *spoe.Message) (bool, []spoe.Action, error) {
	ssl, host, pathq, cookieValue, err := extractOAuth2Args(msg)
	if err != nil {
		return false, nil, fmt.Errorf("unable to extract origin URL: %v", err)
	}

	domain := extractDomainFromHost(host)

	_, err = oa.options.ClientsStore.GetClient(domain)
	if err == ErrOIDCClientConfigNotFound {
		return false, nil, nil
	} else if err != nil {
		return false, nil, fmt.Errorf("unable to find an oidc client for domain %s", domain)
	}

	// Verify the cookie to make sure the user is authenticated
	if cookieValue != "" {
		err := oa.checkCookie(cookieValue, extractDomainFromHost(host))
		if err != nil {
			return false, nil, err
		} else {
			return true, nil, nil
		}
	}

	currentTime := time.Now()

	var state State
	state.Timestamp = currentTime
	state.PathAndQueryString = pathq
	state.SSL = ssl
	state.Signature = oa.computeStateSignature(&state)

	stateBytes, err := msgpack.Marshal(state)
	if err != nil {
		return false, nil, fmt.Errorf("unable to marshal the state")
	}

	var authorizationURL string
	err = oa.withOAuth2Config(domain, func(config oauth2.Config) error {
		authorizationURL = config.AuthCodeURL(base64.StdEncoding.EncodeToString(stateBytes))
		return nil
	})
	if err != nil {
		return false, nil, fmt.Errorf("unable to build authorize url: %w", err)
	}

	return false, []spoe.Action{BuildRedirectURLMessage(authorizationURL)}, nil
}

func (oa *OIDCAuthenticator) handleOAuth2Logout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := http.Cookie{
			Name:     oa.options.CookieName,
			Path:     "/",
			HttpOnly: true,
			Secure:   oa.options.CookieSecure,
		}
		http.SetCookie(w, &c)

		// TODO: make a call to the logout endpoint of the authz server assuming it is implemented.
		// RFC is currently in draft state: https://openid.net/specs/openid-connect-session-1_0.html

		fmt.Fprint(w, LogoutPageTemplate)
	}
}

func (oa *OIDCAuthenticator) handleOAuth2Callback(tmpl *template.Template, errorTmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stateB64Payload := r.URL.Query().Get("state")
		if stateB64Payload == "" {
			logrus.Error("cannot extract the state query param")
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		domain := extractDomainFromHost(r.Host)

		var oauth2Token *oauth2.Token
		err := oa.withOAuth2Config(domain, func(config oauth2.Config) error {
			token, err := config.Exchange(r.Context(), r.URL.Query().Get("code"))
			oauth2Token = token
			return err
		})
		if err != nil {
			logrus.Errorf("unable to retrieve OAuth2 token: %v", err)
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		// Extract the ID Token from OAuth2 token.
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			logrus.Errorf("unable to extract the raw id_token: %v", err)
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		// Parse and verify ID Token payload.
		idToken, err := oa.verifyIDToken(r.Context(), domain, rawIDToken)
		if err != nil {
			logrus.Errorf("unable to verify the ID token: %v", err)
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		stateJSONPayload, err := base64.StdEncoding.DecodeString(stateB64Payload)
		if err != nil {
			logrus.Errorf("unable to decode origin URL from state: %v", err)
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		var state State
		err = msgpack.Unmarshal(stateJSONPayload, &state)
		if err != nil {
			logrus.Errorf("unable to unmarshal the state payload: %v", err)
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		if state.Timestamp.Add(30 * time.Second).Before(time.Now()) {
			logrus.Errorf("state value has expired: %v", err)
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		scheme := "https"
		if !state.SSL {
			scheme = "http"
		}
		url := fmt.Sprintf("%s://%s%s", scheme, r.Host, state.PathAndQueryString)
		logrus.Debugf("target url request by user %s", url)
		signature := oa.computeStateSignature(&state)
		if signature != state.Signature {
			err = errorTmpl.Execute(w, struct{ URL string }{URL: url})
			if err != nil {
				logrus.Errorf("unable to render error template: %v", err)
				http.Error(w, "Bad request", http.StatusBadRequest)
				return
			}
			return
		}

		encryptedIDToken, err := oa.encryptor.Encrypt(rawIDToken)

		if err != nil {
			logrus.Errorf("unable to encrypt the ID token: %v", err)
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
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
			HttpOnly: true,
			Secure:   oa.options.CookieSecure,
		}

		http.SetCookie(w, &cookie)

		err = tmpl.Execute(w, struct{ URL string }{URL: string(url)})
		if err != nil {
			logrus.Errorf("unable to render redirect template: %v", err)
			http.Error(w, "Bad request", http.StatusBadRequest)
		}
	}
}
