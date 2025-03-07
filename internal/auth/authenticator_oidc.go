package auth

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"text/template"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/coreos/go-oidc/v3/oidc"
	cache "github.com/go-pkgz/expirable-cache/v3"
	action "github.com/negasus/haproxy-spoe-go/action"
	message "github.com/negasus/haproxy-spoe-go/message"

	"golang.org/x/oauth2"
)

var callbackServerMux = http.NewServeMux()

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

	// OpenID "state" lifetime, default value is 5 minutes as
	// recommended in https://github.com/OpenIDC/mod_auth_openidc/wiki/Cookies#state-cookie.
	StateTTL time.Duration

	// Optional support contact information.
	SupportEmailAddress string
	SupportEmailSubject string

	// The addr interface the callback will be exposed on.
	CallbackAddr string

	// The object retrieving the OIDC client configuration from the given domain
	ClientsStore OIDCClientsStore

	// Indicates whether the client info have to be read from spoe messages
	ReadClientInfoFromMessages bool
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
	pkceVerifierCache cache.Cache[string, string]

	options OIDCAuthenticatorOptions
}

type OAuthArgs struct {
	ssl              bool
	host             string
	pathq            string
	clientid         string
	clientsecret     string
	redirecturl      string
	cookie           string
	tokenClaims      []string
	tokenExpressions []OAuthTokenExpression
}

// errorTemplateContext contains extra fields to render error messages.
type errorTemplateContext struct {
	SupportEmail        string
	SupportEmailSubject string
}

type errorTemplates struct {
	redirectErr       *template.Template
	badRequestErr     *template.Template
	internalServerErr *template.Template
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
		logrus.Fatalf("unable to read the html page for redirecting: %s", err)
	}

	// Load error templates.
	var errorsTmpl errorTemplates

	errorsTmpl.redirectErr, err = template.New(errNameRedirect).Parse(RedirectErrorPageTemplate)
	if err != nil {
		logrus.Fatalf("unable to read the html page for redirect errors: %s", err)
	}

	errorsTmpl.badRequestErr, err = template.New(errNameBadRequest).Parse(BadRequestTemplate)
	if err != nil {
		logrus.Fatalf("unable to read the html page for bad request error: %s", err)
	}

	errorsTmpl.internalServerErr, err = template.New(errNameInternal).Parse(InternalServerErrorTemplate)
	if err != nil {
		logrus.Fatalf("unable to read the html page for internal server error: %s", err)
	}

	oa := &OIDCAuthenticator{
		provider:          provider,
		options:           options,
		signatureComputer: NewHmacSha256Computer(options.SignatureSecret),
		encryptor:         NewAESEncryptor(options.EncryptionSecret),
		pkceVerifierCache: cache.NewCache[string, string](),
	}

	go func() {
		callbackServerMux.HandleFunc(options.RedirectCallbackPath, oa.handleOAuth2Callback(tmpl, errorsTmpl, errorTemplateContext{
			SupportEmail:        options.SupportEmailAddress,
			SupportEmailSubject: options.SupportEmailSubject,
		}))
		callbackServerMux.HandleFunc(options.LogoutPath, oa.handleOAuth2Logout())
		logrus.Infof("OIDC API is exposed on %s", options.CallbackAddr)
		callbackServerMux.HandleFunc(options.HealthCheckPath, handleHealthCheck)

		logrus.Fatalln(http.ListenAndServe(options.CallbackAddr, callbackServerMux))
	}()

	return oa
}

func handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte("OK"))
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

func (oa *OIDCAuthenticator) verifyIDToken(context context.Context, oidcClientConfig *OIDCClientConfig, rawIDToken string) (*oidc.IDToken, error) {
	verifier := oa.provider.Verifier(&oidc.Config{ClientID: oidcClientConfig.ClientID})

	// Parse and verify ID Token payload.
	idToken, err := verifier.Verify(context, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("unable to verify ID Token: %w", err)
	}
	return idToken, nil
}

func (oa *OIDCAuthenticator) decryptCookie(cookieValue string, oidcClientConfig *OIDCClientConfig) (*oidc.IDToken, error) {
	idToken, err := oa.encryptor.Decrypt(cookieValue)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt session cookie: %w", err)
	}

	token, err := oa.verifyIDToken(context.Background(), oidcClientConfig, idToken)
	return token, err
}

func extractOAuth2Args(msg *message.Message, readClientInfoFromMessages bool, log *logrus.Entry) (OAuthArgs, error) {
	var cookie string
	var clientid, clientsecret, redirecturl *string
	var tokenClaims []string
	var tokenExpressions []OAuthTokenExpression

	// ssl
	sslValue, ok := msg.KV.Get("arg_ssl")
	if !ok {
		return OAuthArgs{}, ErrSSLArgNotFound
	}
	ssl, ok := sslValue.(bool)
	if !ok {
		return OAuthArgs{}, fmt.Errorf("SSL is not a bool: %+v", sslValue)
	}

	// host
	hostValue, ok := msg.KV.Get("arg_host")
	if !ok {
		return OAuthArgs{}, ErrHostArgNotFound
	}
	host, ok := hostValue.(string)
	if !ok {
		return OAuthArgs{}, fmt.Errorf("host is not a string: %+v", hostValue)
	}

	// pathq
	pathqValue, ok := msg.KV.Get("arg_pathq")
	if !ok {
		return OAuthArgs{}, ErrPathqArgNotFound
	}
	pathq, ok := pathqValue.(string)
	if !ok {
		return OAuthArgs{}, fmt.Errorf("pathq is not a string: %+v", pathqValue)
	}

	// cookie
	cookieValue, ok := msg.KV.Get("arg_cookie")
	if ok {
		cookie, ok = cookieValue.(string)
		if !ok && logrus.IsLevelEnabled(logrus.DebugLevel) {
			log.WithField("request_cookie_raw", cookieValue).Debug("Request cookie is not a string or not defined")
		}

		// Token claims
		tokenClaimsValue, ok := msg.KV.Get("arg_token_claims")
		if ok && tokenClaimsValue != nil {
			strV, ok := tokenClaimsValue.(string)
			if !ok {
				return OAuthArgs{}, fmt.Errorf("arg_token_claims is not a string: %+v", tokenClaimsValue)
			}

			encTokenClaims := strings.Split(strV, " ")

			tokenClaims = make([]string, 0, len(encTokenClaims))

			// Decode each claim as they can contain spaces and other characters.
			for i := range encTokenClaims {
				val, err := decodeRequestValue(encTokenClaims[i])
				if err != nil {
					return OAuthArgs{}, fmt.Errorf("arg_token_claims %q can not be decoded: %w", encTokenClaims[i], err)
				}

				tokenClaims = append(tokenClaims, val)
			}
		}

		// Token expressions.
		tokenExpressionsValue, ok := msg.KV.Get("arg_token_expressions")
		if ok && tokenExpressionsValue != nil {
			strV, ok := tokenExpressionsValue.(string)
			if !ok {
				return OAuthArgs{}, fmt.Errorf("arg_token_expressions is not a string: %+v", tokenExpressionsValue)
			}

			var err error
			tokenExpressions, err = parseTokenExpressions(strV)
			if err != nil {
				return OAuthArgs{}, fmt.Errorf("can not parse arg_token_expressions: %w", err)
			}
		}
	}

	if readClientInfoFromMessages {
		// client_id
		clientidValue, ok := msg.KV.Get("arg_client_id")
		if !ok {
			logrus.Debugf("clientid is not defined : %+v", clientidValue)
		} else {
			clientidStr, ok := clientidValue.(string)
			if !ok {
				logrus.Debugf("clientid is not a string: %+v", clientidValue)
			} else {
				clientid = new(string)
				*clientid = clientidStr
			}
		}

		// client_secret
		clientsecretValue, ok := msg.KV.Get("arg_client_secret")
		if !ok {
			logrus.Debugf("clientsecret is not defined : %+v", clientsecretValue)
		} else {
			clientsecretStr, ok := clientsecretValue.(string)
			if !ok {
				logrus.Debugf("clientsecret is not a string: %+v", clientsecretValue)
			} else {
				clientsecret = new(string)
				*clientsecret = clientsecretStr
			}
		}

		// redirect_url
		redirecturlValue, ok := msg.KV.Get("arg_redirect_url")
		if !ok {
			logrus.Debugf("redirecturl is not defined : %+v", redirecturlValue)
		} else {
			redirecturlStr, ok := redirecturlValue.(string)
			if !ok {
				logrus.Debugf("redirecturl is not a string: %+v", redirecturlValue)
			} else {
				redirecturl = new(string)
				*redirecturl = redirecturlStr
			}
		}
	}

	if clientid == nil || redirecturl == nil {
		temp := ""
		clientid = &temp
		redirecturl = &temp
	}

	return OAuthArgs{
			ssl:              ssl,
			host:             host,
			pathq:            pathq,
			cookie:           cookie,
			clientid:         *clientid,
			clientsecret:     *clientsecret,
			redirecturl:      *redirecturl,
			tokenClaims:      tokenClaims,
			tokenExpressions: tokenExpressions,
		},
		nil
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
func (oa *OIDCAuthenticator) Authenticate(msg *message.Message) (bool, []action.Action, error) {
	var log = logrus.WithField("context", "Authenticate")

	oauthArgs, err := extractOAuth2Args(msg, oa.options.ReadClientInfoFromMessages, log)
	if err != nil {
		return false, nil, fmt.Errorf("unable to extract origin URL: %v", err)
	}

	domain := extractDomainFromHost(oauthArgs.host)

	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		log = log.WithFields(logrus.Fields{
			"ssl":                       oauthArgs.ssl,
			"host":                      oauthArgs.host,
			"domain":                    domain,
			"request_token_claims":      oauthArgs.tokenClaims,
			"request_token_expressions": oauthArgs.tokenExpressions,
		})

		log.WithFields(logrus.Fields{
			"cookie": oauthArgs.cookie,
			"pathq":  oauthArgs.pathq,
		}).Debug("OAuth2 authenticate request")
	}

	if oa.options.ReadClientInfoFromMessages && oauthArgs.clientid != "" {
		oa.options.ClientsStore.AddClient(domain, oauthArgs.clientid, oauthArgs.clientsecret, oauthArgs.redirecturl)
	}

	oidcClientConfig, err := oa.options.ClientsStore.GetClient(domain)
	if err != nil {
		return false, nil, fmt.Errorf("unable to find an oidc client for domain %s", domain)
	}

	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		log = log.WithFields(logrus.Fields{
			"client_id":           oidcClientConfig.ClientID,
			"client_redirect_url": oidcClientConfig.RedirectURL,
		})

		log.Debug("OAuth2 authenticate request")
	}

	// Verify the cookie to make sure the user is authenticated
	if oauthArgs.cookie != "" {
		// Here we trust that the cookies were encrypted and authenticated
		// by the SPOE Agent's encryption key.
		idToken, err := oa.decryptCookie(oauthArgs.cookie, oidcClientConfig)
		if err != nil {
			// CoreOS/go-oidc does not have error types, so the errors are handled using strings
			// comparison.
			if errors.Is(err, &oidc.TokenExpiredError{}) || strings.Contains(err.Error(), "oidc:") {
				authorizationURL, e := oa.buildAuthorizationURL(domain, oauthArgs)
				if e != nil {
					return false, nil, e
				}

				log.WithError(err).Infof("Authentication failed, redirecting to OIDC provider %s", authorizationURL)

				return false, []action.Action{BuildRedirectURLMessage(authorizationURL)}, nil
			}

			log.WithError(err).Info("Unauthenticated: can not decryptCookie")

			return false, nil, err
		}

		// Parse TokenClaims and Token Expressions and set the values in response.
		if len(oauthArgs.tokenClaims) == 0 && len(oauthArgs.tokenExpressions) == 0 {
			// Skip parsing.
			log.Debug("No token claims and token expressions requested, shortcut authentication with success")
			return true, nil, nil
		}

		// Parse Token.
		tokenClaims, err := parseTokenClaims(idToken)
		if err != nil {
			log.WithError(err).Error("Can not parse ID Token claims")
			return false, []action.Action{BuildHasErrorMessage()}, fmt.Errorf("can not parse ID Token claims: %w", err)
		}

		if logrus.IsLevelEnabled(logrus.DebugLevel) {
			log = log.WithField("id_token_claims", tokenClaims)
			log.Debug("Parsed Token claims")
		}

		var actions []action.Action

		// Parse token claims.
		if len(oauthArgs.tokenClaims) != 0 {
			// Extract token claims.
			claimsActs := BuildTokenClaimsMessage(tokenClaims, oauthArgs.tokenClaims)

			if logrus.IsLevelEnabled(logrus.DebugLevel) {
				log = log.WithField("response_actions_token_claims", claimsActs)
			}

			actions = append(actions, claimsActs...)
		}

		// Parse and evaluate token expressions.
		if len(oauthArgs.tokenExpressions) != 0 {
			expr, err := EvaluateTokenExpressions(tokenClaims, oauthArgs.tokenExpressions)
			if err != nil {
				return false, []action.Action{BuildHasErrorMessage()}, fmt.Errorf("can not evaluate ID Token expressions: %w", err)
			}

			if logrus.IsLevelEnabled(logrus.DebugLevel) {
				log = log.WithField("response_actions_token_expressions", expr)
			}

			actions = append(actions, expr...)
		}

		if logrus.IsLevelEnabled(logrus.DebugLevel) {
			log.Debug("Computed SPOE response")
		}

		return true, actions, nil
	}

	authorizationURL, err := oa.buildAuthorizationURL(domain, oauthArgs)
	if err != nil {
		return false, nil, err
	}

	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		log = log.WithField("redirect_authorization_url", authorizationURL)
		log.Debug("Sending redirect message to Authorization URL")
	}

	return false, []action.Action{BuildRedirectURLMessage(authorizationURL)}, nil
}

func (oa *OIDCAuthenticator) buildAuthorizationURL(domain string, oauthArgs OAuthArgs) (string, error) {
	currentTime := time.Now()

	var state State
	state.Timestamp = currentTime
	state.PathAndQueryString = oauthArgs.pathq
	state.SSL = oauthArgs.ssl
	state.Signature = oa.computeStateSignature(&state)

	stateBytes, err := msgpack.Marshal(state)
	if err != nil {
		return "", fmt.Errorf("unable to marshal the state")
	}

	var authorizationURL string
	pkceVerifier := oauth2.GenerateVerifier()
	stateStr := base64.StdEncoding.EncodeToString(stateBytes)
	cacheTTL := time.Second * 3600
	if oa.options.CookieTTL != 0 {
		cacheTTL = oa.options.CookieTTL
	}
	oa.pkceVerifierCache.Set(stateStr, pkceVerifier, cacheTTL)
	err = oa.withOAuth2Config(domain, func(config oauth2.Config) error {
		authorizationURL = config.AuthCodeURL(stateStr, oauth2.S256ChallengeOption(pkceVerifier))
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("unable to build authorize url: %w", err)
	}

	return authorizationURL, nil
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

func (oa *OIDCAuthenticator) handleOAuth2Callback(tmpl *template.Template, errorsTmpl errorTemplates, errorsCtx errorTemplateContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var logger *logrus.Entry = logrus.WithFields(logrus.Fields{
			"client":  r.RemoteAddr,
			"context": "OAuth2Callback",
		})

		if logrus.IsLevelEnabled(logrus.DebugLevel) {
			logger = logger.WithFields(logrus.Fields{
				"request_url": r.RequestURI,
				"query":       r.URL.Query(),
				"state":       r.URL.Query().Get("state"),
				"code":        r.URL.Query().Get("code"),
			})
			logger.Debug("Received callback request")
		}

		stateB64Payload := r.URL.Query().Get("state")
		if stateB64Payload == "" {
			logger.Error("cannot extract the state query param")
			writeError(logger, http.StatusBadRequest, w, errorsTmpl, &errorsCtx)
			return
		}

		domain := extractDomainFromHost(r.Host)

		oidcClientConfig, err := oa.options.ClientsStore.GetClient(domain)
		if err != nil {
			logger.WithField("domain", domain).WithError(err).Error("Can not find OAuth2 client for the given domain")
			writeError(logger, http.StatusBadRequest, w, errorsTmpl, &errorsCtx)
			return
		}

		pkceVerifier, ok := oa.pkceVerifierCache.Get(stateB64Payload)
		if !ok {
			logrus.Error("cannot retrieve pkce verifier")
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		var oauth2Token *oauth2.Token
		err = oa.withOAuth2Config(domain, func(config oauth2.Config) error {
			token, err := config.Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(pkceVerifier))
			oauth2Token = token
			return err
		})
		if err != nil {
			logger.WithError(err).Error("unable to retrieve OAuth2 token")
			writeError(logger, http.StatusBadRequest, w, errorsTmpl, &errorsCtx)
			return
		}

		// Extract the ID Token from OAuth2 token.
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			logger.Errorf("unable to extract the raw id_token: %v", err)
			writeError(logger, http.StatusBadRequest, w, errorsTmpl, &errorsCtx)
			return
		}

		// Parse and verify ID Token payload.
		idToken, err := oa.verifyIDToken(r.Context(), oidcClientConfig, rawIDToken)
		if err != nil {
			logger.WithError(err).Error("unable to verify the ID token")
			writeError(logger, http.StatusBadRequest, w, errorsTmpl, &errorsCtx)
			return
		}

		stateJSONPayload, err := base64.StdEncoding.DecodeString(stateB64Payload)
		if err != nil {
			logger.WithError(err).Error("unable to decode origin URL from state")
			writeError(logger, http.StatusBadRequest, w, errorsTmpl, &errorsCtx)
			return
		}

		var state State
		err = msgpack.Unmarshal(stateJSONPayload, &state)
		if err != nil {
			logger.WithError(err).Error("unable to unmarshal the state payload")
			writeError(logger, http.StatusBadRequest, w, errorsTmpl, &errorsCtx)
			return
		}

		var nowTS = time.Now()
		if state.Timestamp.Add(oa.options.StateTTL).Before(nowTS) {
			logger.WithFields(logrus.Fields{
				"state_timestamp":            state.Timestamp,
				"state_timestamp_check_time": nowTS,
				"state_validity_duration":    oa.options.StateTTL,
			}).Error("state value has expired")
			writeError(logger, http.StatusBadRequest, w, errorsTmpl, &errorsCtx)
			return
		}

		scheme := "https"
		if !state.SSL {
			scheme = "http"
		}
		url := fmt.Sprintf("%s://%s%s", scheme, r.Host, state.PathAndQueryString)
		logger.Debugf("target url request by user %s", url)
		signature := oa.computeStateSignature(&state)
		if signature != state.Signature {
			err = errorsTmpl.redirectErr.Execute(w, struct{ URL string }{URL: url})
			if err != nil {
				logger.WithError(err).Error("unable to render error template")
				http.Error(w, "Server error", http.StatusInternalServerError)
				return
			}
			return
		}

		encryptedIDToken, err := oa.encryptor.Encrypt(rawIDToken)
		if err != nil {
			logger.WithError(err).Error("unable to encrypt the ID token")
			writeError(logger, http.StatusInternalServerError, w, errorsTmpl, &errorsCtx)
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
			logger.WithError(err).Error("unable to render redirect template")
			writeError(logger, http.StatusBadRequest, w, errorsTmpl, &errorsCtx)
		}
	}
}

func parseTokenExpressions(arg string) ([]OAuthTokenExpression, error) {
	expessions := strings.Split(arg, " ")

	var result = make([]OAuthTokenExpression, 0, len(expessions))

	for i := range expessions {
		expression_val, err := decodeRequestValue(expessions[i])
		if err != nil {
			return nil, fmt.Errorf("Can not decode token expression value %q: %w", expessions[i], err)
		}

		vals := strings.Split(expression_val, ";")

		valsLen := len(vals)

		if valsLen < 2 {
			return nil, fmt.Errorf(
				"%w: not enough arguments, minimum number of arguments is 2, given expression is %q",
				ErrParseTokenExpressionRequest, expression_val)
		}

		var expr = OAuthTokenExpression{}

		switch vals[0] {
		case operationExists:
			// Format is "{{ operation }};{{ token claims path }}"
			expr.Operation = exists

			if valsLen != 2 {
				return nil, fmt.Errorf(
					"%w: operation %q requires exactly 2 arguments, %d given, request: %q",
					ErrParseTokenExpressionRequest, operationExists, valsLen, expression_val)
			}

			expr.TokenClaim = vals[1]

		case operationDoesNotExist:
			expr.Operation = doesNotExist

			if valsLen != 2 {
				return nil, fmt.Errorf(
					"%w: operation %q requires exactly 2 arguments, %d given, request: %q",
					ErrParseTokenExpressionRequest, operationDoesNotExist, valsLen, expression_val)
			}

			expr.TokenClaim = vals[1]

		case operationIn:
			expr.Operation = in

			if valsLen != 3 {
				return nil, fmt.Errorf(
					"%w: operation %q requires exactly 3 arguments, %d given, request: %q",
					ErrParseTokenExpressionRequest, operationIn, valsLen, expression_val)
			}

			expr.TokenClaim = vals[1]
			expr.RawValue = vals[2]

		case operationNotIn:
			expr.Operation = notIn

			if valsLen != 3 {
				return nil, fmt.Errorf(
					"%w: operation %q requires exactly 3 arguments, %d given, request: %q",
					ErrParseTokenExpressionRequest, operationNotIn, valsLen, expression_val)
			}

			expr.TokenClaim = vals[1]
			expr.RawValue = vals[2]

		default:
			return nil, fmt.Errorf(
				"%w: unsupported operation %q in a token expression %q",
				ErrParseTokenExpressionRequest, vals[i], expression_val)
		}

		result = append(result, expr)
	}

	return result, nil
}

func parseTokenClaims(idToken *oidc.IDToken) (*gjson.Result, error) {
	var claimsData json.RawMessage

	if err := idToken.Claims(&claimsData); err != nil {
		return nil, fmt.Errorf("unable to load OIDC claims: %w", err)
	}

	claimsVals := gjson.ParseBytes(claimsData)

	return &claimsVals, nil
}

func writeError(logger *logrus.Entry, code int, w http.ResponseWriter, errorsTmpl errorTemplates, errorsCtx *errorTemplateContext) {
	switch code {
	case http.StatusInternalServerError:
		w.WriteHeader(http.StatusBadRequest)
		err := errorsTmpl.internalServerErr.Execute(w, &errorsCtx)
		if err != nil {
			logger.WithError(err).Error("unable to render error template")
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}

	case http.StatusBadRequest:
		w.WriteHeader(http.StatusBadRequest)
		err := errorsTmpl.badRequestErr.Execute(w, errorsCtx)
		if err != nil {
			logger.WithError(err).Error("unable to render error template", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}

	default:
		w.WriteHeader(http.StatusInternalServerError)
		err := errorsTmpl.internalServerErr.Execute(w, &errorsCtx)
		if err != nil {
			logger.WithError(err).Error("unable to render error template")
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}

	}
}
