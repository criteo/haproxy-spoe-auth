package auth

import "errors"

// ErrNoCredential error thrown when no credentials are provided with the request
var ErrNoCredential = errors.New("No credentials provided")

// ErrBadAuthorizationValue error thrown when the authorization header value is in wrong format
var ErrBadAuthorizationValue = errors.New("Bad authorization value provided")

// ErrWrongCredentials error thrown when credentials provided by user are wrong
var ErrWrongCredentials = errors.New("Wrong credentials")

// ErrUserDoesntExist error thrown when provided user does not exist
var ErrUserDoesntExist = errors.New("User does not exist")

// ErrTooManyUsersMatching error thrown when too many users are retrieved upon LDAP search
var ErrTooManyUsersMatching = errors.New("There are too many user matching this request")
