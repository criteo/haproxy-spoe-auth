package auth

import "errors"

// ErrNoCredential error thrown when no credentials are provided with the request
var ErrNoCredential = errors.New("no credentials provided")

// ErrBadAuthorizationValue error thrown when the authorization header value is in wrong format
var ErrBadAuthorizationValue = errors.New("dad authorization value provided")

// ErrWrongCredentials error thrown when credentials provided by user are wrong
var ErrWrongCredentials = errors.New("wrong credentials")

// ErrUserDoesntExist error thrown when provided user does not exist
var ErrUserDoesntExist = errors.New("user does not exist")

// ErrTooManyUsersMatching error thrown when too many users are retrieved upon LDAP search
var ErrTooManyUsersMatching = errors.New("there are too many user matching this request")
