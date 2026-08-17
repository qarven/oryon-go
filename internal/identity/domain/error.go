package domain

import "errors"

var (
	// ErrUserNotFound indicates no user matches the lookup criteria.
	ErrUserNotFound = errors.New("user not found")
	// ErrUserAlreadyExists indicates a user with the same email already exists.
	ErrUserAlreadyExists = errors.New("user already exists")
	// ErrCredentialNotFound indicates no credential matches the lookup criteria.
	ErrCredentialNotFound = errors.New("credential not found")
	// ErrAccountNotFound indicates no account matches the lookup criteria.
	ErrAccountNotFound = errors.New("account not found")
)
