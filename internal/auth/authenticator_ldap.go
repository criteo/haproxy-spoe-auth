package auth

import (
	"encoding/base64"
	"fmt"
	"strings"

	spoe "github.com/criteo/haproxy-spoe-go"
	"github.com/sirupsen/logrus"
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
		return fmt.Errorf("search request failed: %w", err)
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
		if e, ok := err.(*ldap.Error); ok && e.ResultCode == 49 { // Invalid credentials
			return ErrWrongCredentials
		}
		return fmt.Errorf("unable to bind user: %w", err)
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
func (la *LDAPAuthenticator) Authenticate(msg *spoe.Message) (bool, []spoe.Action, error) {
	var authorization string

	for msg.Args.Next() {
		arg := msg.Args.Arg

		if arg.Name == "authorization" {
			var ok bool
			authorization, ok = arg.Value.(string)
			if !ok {
				return false, nil, nil
			}
		}
	}

	if authorization == "" {
		logrus.Debug("Authorization header is empty")
		return false, nil, nil
	}

	username, password, err := parseBasicAuth(authorization)

	if err != nil {
		return false, nil, fmt.Errorf("unable to parse basic auth header")
	}

	err = verifyCredentials(&la.connectionDetails, username, password)

	if err != nil {
		if err == ErrUserDoesntExist {
			logrus.Debugf("user %s does not exist", username)
			return false, nil, nil
		} else if err == ErrWrongCredentials {
			logrus.Debug("wrong credentials")
			return false, nil, nil
		}
		return false, nil, err
	}

	logrus.Debug("User is authenticated")
	return true, nil, nil
}
