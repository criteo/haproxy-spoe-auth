package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"strings"

	spoe "github.com/criteo/haproxy-spoe-go"
	ldap "gopkg.in/ldap.v3"
)

// ErrNoCredential error thrown when no credentials are provided with the request
var ErrNoCredential = fmt.Errorf("No credentials provided")

// ErrBadAuthorizationValue error thrown when the authorization header value is in wrong format
var ErrBadAuthorizationValue = fmt.Errorf("Bad authorization value provided")

// ErrWrongCredentials error thrown when credentials provided by user are wrong
var ErrWrongCredentials = fmt.Errorf("Wrong credentials")

// ErrUserDoesntExist error thrown when provided user does not exist
var ErrUserDoesntExist = fmt.Errorf("User does not exist")

const binduser = "cn=admin,dc=example,dc=com"
const bindpassword = "password"

func verifyCredentials(username string, password string) error {
	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", "openldap", 389))
	if err != nil {
		return err
	}
	defer l.Close()

	// First bind with a read only user
	err = l.Bind(binduser, bindpassword)
	if err != nil {
		return err
	}

	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false,
		fmt.Sprintf("(cn=%s)", username),
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
		return errors.New("There are too many user matching this request")
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
		return "", "", fmt.Errorf("Format for basic auth must be user:password")
	}
	return cs[:s], cs[s+1:], nil
}

func handleAuthentication(message *spoe.Message) error {
	authorization, ok := message.Args["authorization"].(string)

	if !ok {
		return ErrNoCredential
	}

	username, password, err := parseBasicAuth(authorization)

	if err != nil {
		return err
	}

	err = verifyCredentials(username, password)

	if err != nil {
		return err
	}

	return nil
}

func main() {
	agent := spoe.New(func(messages []spoe.Message) ([]spoe.Action, error) {
		authenticated := false
		for _, msg := range messages {
			fmt.Println(msg)
			if msg.Name != "try-auth" {
				continue
			}

			err := handleAuthentication(&msg)

			if err != nil {
				fmt.Println(err)
				continue
			}

			authenticated = true
			continue
		}

		return []spoe.Action{
			spoe.ActionSetVar{
				Name:  "is_authenticated",
				Scope: spoe.VarScopeSession,
				Value: authenticated,
			},
		}, nil
	})

	if err := agent.ListenAndServe(":8081"); err != nil {
		log.Fatal(err)
	}
}
