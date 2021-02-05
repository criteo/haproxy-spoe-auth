package main

import (
	"flag"

	"github.com/clems4ever/haproxy-spoe-auth/internal/agent"
	"github.com/clems4ever/haproxy-spoe-auth/internal/auth"
)

func main() {
	interfaceAddrPtr := flag.String("addr", ":8081", "The port of the agent")

	oidcProviderPtr := flag.String("oidc-provider", "", "The URL to the OIDC provider")
	clientIDPtr := flag.String("client-id", "oidc-proxy", "The client ID for your application")
	clientSecretPtr := flag.String("client-secret", "", "The client secret for your application")
	redirectURLPtr := flag.String("redirect-url", "/oauth2/callback", "The redirect URL for the OAuth2 transaction")
	callbackAddrPtr := flag.String("callback-addr", ":5000", "The interface to expose the callback on")
	cookieNamePtr := flag.String("cookie-name", "authsession", "The name of the cookie holding the session")
	cookieDomainPtr := flag.String("cookie-domain", "", "The domain the cookie holding the session must be set to")
	signatureSecretPtr := flag.String("signature-secret", "", "The secret used to sign the redirection URL and the cookie")

	flag.Parse()

	if oidcProviderPtr == nil || (oidcProviderPtr != nil && *oidcProviderPtr == "") {
		flag.PrintDefaults()
		return
	}

	if clientIDPtr == nil || (clientIDPtr != nil && *clientIDPtr == "") {
		flag.PrintDefaults()
		return
	}

	if clientSecretPtr == nil || (clientSecretPtr != nil && *clientSecretPtr == "") {
		flag.PrintDefaults()
		return
	}

	if redirectURLPtr == nil || (redirectURLPtr != nil && *redirectURLPtr == "") {
		flag.PrintDefaults()
		return
	}

	if callbackAddrPtr == nil || (callbackAddrPtr != nil && *callbackAddrPtr == "") {
		flag.PrintDefaults()
		return
	}

	if signatureSecretPtr == nil || (signatureSecretPtr != nil && *signatureSecretPtr == "") {
		flag.PrintDefaults()
		return
	}

	if cookieDomainPtr == nil || (cookieDomainPtr != nil && *cookieDomainPtr == "") {
		flag.PrintDefaults()
		return
	}

	oidcAuthenticator := auth.NewOIDCAuthenticator(auth.OIDCAuthenticatorOptions{
		ProviderURL:     *oidcProviderPtr,
		ClientID:        *clientIDPtr,
		ClientSecret:    *clientSecretPtr,
		RedirectURL:     *redirectURLPtr,
		CallbackAddr:    *callbackAddrPtr,
		CookieName:      *cookieNamePtr,
		CookieDomain:    *cookieDomainPtr,
		SignatureSecret: *signatureSecretPtr,
	})

	agent.StartAgent(*interfaceAddrPtr, oidcAuthenticator)
}
