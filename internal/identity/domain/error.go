package domain

import "errors"

var (
	// ErrIdentityNotFound indicates no identity matches the lookup criteria.
	ErrIdentityNotFound = errors.New("identity not found")
	// ErrIdentityAlreadyExists indicates an identity with the same email already exists.
	ErrIdentityAlreadyExists = errors.New("identity already exists")
	// ErrIdentityCredentialNotFound indicates no identity credential matches the lookup criteria.
	ErrIdentityCredentialNotFound = errors.New("identity credential not found")
	// ErrAccountNotFound indicates no account matches the lookup criteria.
	ErrAccountNotFound = errors.New("account not found")
)
