package auth

import (
	"encoding/base64"
	"fmt"
	"strings"

	spoe "github.com/criteo/haproxy-spoe-go"
	"gopkg.in/ldap.v3"
)

// LDAPConnectionDetails represents the connection details
type LDAPConnectionDetails struct {
	Hostname   string
	Port       int
	UserDN     string
	Password   string
	BaseDN     string
	UserFilter string
}

// LDAPAuthenticator is the LDAP implementation of the Authenticator interface
type LDAPAuthenticator struct {
	connectionDetails LDAPConnectionDetails
}

// NewLDAPAuthenticator create an instance of a LDAP authenticator
func NewLDAPAuthenticator(options LDAPConnectionDetails) *LDAPAuthenticator {
	return &LDAPAuthenticator{
		connectionDetails: options,
	}
}

func verifyCredentials(ldapDetails *LDAPConnectionDetails, username, password string) error {
	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", ldapDetails.Hostname, ldapDetails.Port))
	if err != nil {
		return err
	}
	defer l.Close()

	// First bind with a read only user
	err = l.Bind(ldapDetails.UserDN, ldapDetails.Password)
	if err != nil {
		return err
	}

	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		ldapDetails.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false,
		strings.Replace(ldapDetails.UserFilter, "{login}", username, 1),
		[]string{"dn"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		return err
	}

	if len(sr.Entries) == 0 {
		return ErrUserDoesntExist
	}

	if len(sr.Entries) > 1 {
		return ErrTooManyUsersMatching
	}

	userdn := sr.Entries[0].DN

	// Bind as the user to verify their password
	err = l.Bind(userdn, password)
	if err != nil {
		return err
	}

	return nil
}

func parseBasicAuth(auth string) (username, password string, err error) {
	if !strings.HasPrefix(auth, "Basic ") {
		return "", "", fmt.Errorf("%s prefix not found in authorization header", strings.Trim("Basic ", " "))
	}
	c, err := base64.StdEncoding.DecodeString(auth[len("Basic "):])
	if err != nil {
		return "", "", err
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return "", "", ErrBadAuthorizationValue
	}
	return cs[:s], cs[s+1:], nil
}

// Authenticate handle an authentication request coming from HAProxy
func (la *LDAPAuthenticator) Authenticate(msg *spoe.Message) ([]spoe.Action, error) {
	var authorization string

	for msg.Args.Next() {
		arg := msg.Args.Arg

		if arg.Name == "authorization" {
			var ok bool
			authorization, ok = arg.Value.(string)
			if !ok {
				return nil, ErrNoCredential
			}
		}
	}

	if authorization == "" {
		return []spoe.Action{NotAuthenticatedMessage}, nil
	}

	username, password, err := parseBasicAuth(authorization)

	if err != nil {
		return nil, err
	}

	err = verifyCredentials(&la.connectionDetails, username, password)

	if err != nil {
		if err == ErrUserDoesntExist {
			return []spoe.Action{NotAuthenticatedMessage}, nil
		}
		return nil, err
	}

	return []spoe.Action{AuthenticatedMessage}, nil
}
