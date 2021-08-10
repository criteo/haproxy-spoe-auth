package tests

const (
	// ProtectedLdapURL is the URL for the LDAP use case
	ProtectedLdapURL = "http://app1.example.com:9080/"
	// ProtectedOidcURL is the URL for the OIDC use case
	ProtectedOidcURL = "http://app2.example.com:9080/"
	// UnprotectedURL is the URL for the unprotected app
	UnprotectedURL = "http://public.example.com:9080/"

	// LogoutOidcURL is the URL used to log out the user
	LogoutOidcURL = "http://auth.example.com:9080/"
	// LogoutOAuht2URL is the URL used to log out the user
	LogoutOAuth2URL = "http://auth.example.com:9080/"
)
