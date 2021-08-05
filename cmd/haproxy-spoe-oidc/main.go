package main

import (
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/clems4ever/haproxy-spoe-auth/internal/agent"
	"github.com/clems4ever/haproxy-spoe-auth/internal/auth"
)

func main() {
	interfaceAddrPtr := flag.String("addr", ":8081", "The port of the agent")

	oidcProviderPtr := flag.String("oidc-provider", "", "The URL to the OIDC provider")
	clientIDPtr := flag.String("client-id", "", "The client ID for your application")
	clientSecretPtr := flag.String("client-secret", "", "The client secret for your application")
	redirectURLPtr := flag.String("redirect-url", "/oauth2/callback", "The redirect URL for the OAuth2 transaction")
	callbackAddrPtr := flag.String("callback-addr", ":5000", "The interface to expose the callback on")
	cookieNamePtr := flag.String("cookie-name", "authsession", "The name of the cookie holding the session")
	cookieDomainPtr := flag.String("cookie-domain", "", "The domain the cookie holding the session must be set to")
	cookieUnsecurePtr := flag.Bool("cookie-unsecure", true, "Set the secure flag of the session cookie")
	cookieTTLSecondsPtr := flag.Int64("cookie-ttl-seconds", 3600, "The TTL of the cookie in seconds. 0 means the value from the ID token will be used.")
	signatureSecretPtr := flag.String("signature-secret", "", "The secret used to sign the redirection URL")
	encryptionSecretPtr := flag.String("encryption-secret", "", "The secret used to encrypt the ID token stored in the cookie.")
	scopesPtr := flag.String("scopes", "", "The scopes to request authorization for")

	flag.Parse()

	if oidcProviderPtr == nil || (oidcProviderPtr != nil && *oidcProviderPtr == "") {
		flag.PrintDefaults()
		return
	}

	if clientIDPtr == nil || (clientIDPtr != nil && *clientIDPtr == "") {
		flag.PrintDefaults()
		return
	}

	if clientSecretPtr == nil {
		fmt.Println("Client secret not provided")
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

	if encryptionSecretPtr == nil || (encryptionSecretPtr != nil && *encryptionSecretPtr == "") {
		flag.PrintDefaults()
		return
	}

	if cookieDomainPtr == nil || (cookieDomainPtr != nil && *cookieDomainPtr == "") {
		flag.PrintDefaults()
		return
	}

	if cookieTTLSecondsPtr == nil {
		flag.PrintDefaults()
		return
	}

	if cookieUnsecurePtr == nil {
		flag.PrintDefaults()
		return
	}

	if scopesPtr == nil {
		flag.PrintDefaults()
		return
	}

	scopesTmp := strings.Split(*scopesPtr, " ")
	scopes := []string{}
	for _, s := range scopesTmp {
		if s != "" {
			scopes = append(scopes, s)
		}
	}

	agent.StartAgent(*interfaceAddrPtr, auth.NewOIDCAuthenticator(auth.OIDCAuthenticatorOptions{
		OAuth2AuthenticatorOptions: auth.OAuth2AuthenticatorOptions{
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
		},
		ProviderURL:      *oidcProviderPtr,
		EncryptionSecret: *encryptionSecretPtr,
	}))
}
