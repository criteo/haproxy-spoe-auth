package main

import (
	"flag"
	"strings"
	"time"

	"github.com/clems4ever/haproxy-spoe-auth/internal/agent"
	"github.com/clems4ever/haproxy-spoe-auth/internal/auth"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

func main() {
	interfaceAddrPtr := flag.String("addr", ":8081", "The port of the agent")

	oauth2AuthorizationURLPtr := flag.String("authorization-url", "", "The URL to the OAuth2 authorization endpoint")
	oauth2TokenURLPtr := flag.String("token-url", "", "The URL to the OAuth2 access_token endpoint")
	clientIDPtr := flag.String("client-id", "", "The client ID for your application")
	clientSecretPtr := flag.String("client-secret", "", "The client secret for your application")
	redirectURLPtr := flag.String("redirect-url", "/oauth2/callback", "The redirect URL for the OAuth2 transaction")
	callbackAddrPtr := flag.String("callback-addr", ":5000", "The interface to expose the callback on")
	cookieNamePtr := flag.String("cookie-name", "authsession", "The name of the cookie holding the session")
	cookieDomainPtr := flag.String("cookie-domain", "", "The domain the cookie holding the session must be set to")
	cookieUnsecurePtr := flag.Bool("cookie-unsecure", true, "Set the secure flag of the session cookie")
	cookieTTLSecondsPtr := flag.Int64("cookie-ttl-seconds", 3600, "The TTL of the cookie in seconds. 0 means the value from the ID token will be used.")
	signatureSecretPtr := flag.String("signature-secret", "", "The secret used to sign the redirection URL")
	scopesPtr := flag.String("scopes", "", "The scopes to request authorization for")

	flag.Parse()

	if oauth2AuthorizationURLPtr == nil || (oauth2AuthorizationURLPtr != nil && *oauth2AuthorizationURLPtr == "") {
		flag.PrintDefaults()
		logrus.Fatal("No authorization URL provided")
		return
	}

	if oauth2TokenURLPtr == nil || (oauth2TokenURLPtr != nil && *oauth2TokenURLPtr == "") {
		flag.PrintDefaults()
		logrus.Fatal("No token URL provided")
		return
	}

	if clientIDPtr == nil || (clientIDPtr != nil && *clientIDPtr == "") {
		flag.PrintDefaults()
		logrus.Fatal("No client ID provided")
		return
	}

	if clientSecretPtr == nil {
		flag.PrintDefaults()
		logrus.Fatal("No client secret provided")
		return
	}

	if redirectURLPtr == nil || (redirectURLPtr != nil && *redirectURLPtr == "") {
		flag.PrintDefaults()
		logrus.Fatal("No redirect URL provided")
		return
	}

	if callbackAddrPtr == nil || (callbackAddrPtr != nil && *callbackAddrPtr == "") {
		flag.PrintDefaults()
		logrus.Fatal("No callback address provided")
		return
	}

	if signatureSecretPtr == nil || (signatureSecretPtr != nil && *signatureSecretPtr == "") {
		flag.PrintDefaults()
		logrus.Fatal("No signature secret provided")
		return
	}

	if cookieDomainPtr == nil || (cookieDomainPtr != nil && *cookieDomainPtr == "") {
		flag.PrintDefaults()
		logrus.Fatal("No cookie top-domain provided")
		return
	}

	if cookieTTLSecondsPtr == nil {
		flag.PrintDefaults()
		logrus.Fatal("No cookie TTL provided")
		return
	}

	if cookieUnsecurePtr == nil {
		flag.PrintDefaults()
		logrus.Fatal("No cookie unsecure provided")
		return
	}

	if scopesPtr == nil {
		flag.PrintDefaults()
		logrus.Fatal("No scopes provided")
		return
	}

	scopesTmp := strings.Split(*scopesPtr, ",")
	scopes := []string{}
	for _, s := range scopesTmp {
		if s != "" {
			scopes = append(scopes, s)
		}
	}

	agent.StartAgent(*interfaceAddrPtr, auth.NewOAuth2Authenticator(auth.OAuth2AuthenticatorOptions{
		Endpoints: oauth2.Endpoint{
			AuthURL:  *oauth2AuthorizationURLPtr,
			TokenURL: *oauth2TokenURLPtr,
		},
		ClientID:        *clientIDPtr,
		ClientSecret:    *clientSecretPtr,
		RedirectURL:     *redirectURLPtr,
		CallbackAddr:    *callbackAddrPtr,
		CookieName:      *cookieNamePtr,
		CookieDomain:    *cookieDomainPtr,
		CookieSecure:    !*cookieUnsecurePtr,
		CookieTTL:       time.Duration(*cookieTTLSecondsPtr) * time.Second,
		SignatureSecret: *signatureSecretPtr,
		Scopes:          scopes,
	}))
}
