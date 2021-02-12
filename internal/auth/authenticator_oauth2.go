package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"text/template"
	"time"

	"github.com/sirupsen/logrus"

	spoe "github.com/criteo/haproxy-spoe-go"
	"golang.org/x/oauth2"
)

// OAuth2AuthenticatorOptions options to customize to the OAuth2 authenticator
type OAuth2AuthenticatorOptions struct {
	Endpoints    oauth2.Endpoint
	ClientID     string
	ClientSecret string
	RedirectURL  string

	// This is used to sign the redirection URL
	SignatureSecret string

	CookieName       string
	CookieDomain     string
	CookieSecure     bool
	CookieTTLSeconds time.Duration

	Scopes []string

	// The addr interface the callback will be exposed on.
	CallbackAddr string
}

// OAuth2Authenticator is the OAuth2 implementation of the Authenticator interface
type OAuth2Authenticator struct {
	config oauth2.Config

	signatureComputer *HmacSha256Computer

	options OAuth2AuthenticatorOptions
}

// State the content of the state
type State struct {
	URL       string `json:"url"`
	Signature string `json:"sig"`
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-%;:")

func randStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

var nonceSize = 32

// NewOAuth2Authenticator create an instance of an OIDC authenticator
func NewOAuth2Authenticator(options OAuth2AuthenticatorOptions) *OAuth2Authenticator {
	if len(options.SignatureSecret) < 16 {
		logrus.Fatalf("The signature secret should be at least 16 characters, %d provided", len(options.SignatureSecret))
	}

	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := oauth2.Config{
		ClientID:     options.ClientID,
		ClientSecret: options.ClientSecret,
		RedirectURL:  options.RedirectURL,

		// Discovery returns the OAuth2 endpoints.
		Endpoint: options.Endpoints,

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: options.Scopes,
	}
	oauth2Config.Endpoint.AuthStyle = oauth2.AuthStyleInParams

	tmpl, err := template.New("redirect_html").Parse(RedirectPage)
	if err != nil {
		logrus.Fatalf("Unable to read the html page for redirecting")
	}

	errorTmpl, err := template.New("error").Parse(ErrorPage)
	if err != nil {
		logrus.Fatalf("Unable to read the html page for redirecting")
	}

	oa := &OAuth2Authenticator{
		config:            oauth2Config,
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

func extractOAuth2Args(msg *spoe.Message) (string, string, error) {
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
func (oa *OAuth2Authenticator) Authenticate(msg *spoe.Message) ([]spoe.Action, error) {
	originURL, cookieValue, err := extractOAuth2Args(msg)
	if err != nil {
		return nil, fmt.Errorf("Unable to extract origin URL: %v", err)
	}

	// Verify the cookie to make sure the user is authenticated
	if cookieValue != "" {
		data := cookieValue[:nonceSize]
		signature := cookieValue[nonceSize:]
		verified := oa.signatureComputer.VerifySignature(data, signature)
		if verified {
			return []spoe.Action{AuthenticatedMessage}, nil
		}
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

func (oa *OAuth2Authenticator) handleOAuth2Logout() http.HandlerFunc {
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

func (oa *OAuth2Authenticator) handleOAuth2Callback(tmpl *template.Template, errorTmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, err := oa.config.Exchange(r.Context(), r.URL.Query().Get("code"))
		if err != nil {
			logrus.Errorf("Unable to retrieve OAuth2 token: %v", err)
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		// Verify state and errors.
		stateB64Payload := r.URL.Query().Get("state")
		if stateB64Payload == "" {
			http.Error(w, "Cannot extract the state", http.StatusBadRequest)
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

		data := randStringRunes(nonceSize)
		hasher := NewHmacSha256Computer(oa.options.SignatureSecret)

		sig := hasher.ProduceSignature(data)
		dataWithSig := data + sig

		var expiry = time.Now().Add(oa.options.CookieTTLSeconds)

		cookie := http.Cookie{
			Name:     oa.options.CookieName,
			Value:    dataWithSig,
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
