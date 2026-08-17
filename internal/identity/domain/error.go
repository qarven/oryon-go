package domain

import "errors"

var (
	// ErrIdentityCredentialNotFound indicates no identity credential matches the lookup criteria.
	ErrIdentityCredentialNotFound = errors.New("identity credential not found")
	// ErrAccountNotFound indicates no account matches the lookup criteria.
	ErrAccountNotFound = errors.New("account not found")

	// Generic domain errors
	ErrNotFound      = errors.New("resource not found")
	ErrAlreadyExists = errors.New("resource already exists")
	ErrInvalidInput  = errors.New("invalid input")
	ErrUnauthorized  = errors.New("unauthorized")
	ErrForbidden     = errors.New("forbidden")

	// User specific
	ErrUserNotFound      = errors.New("user not found")
	ErrUserAlreadyExists = errors.New("user already exists")
	ErrUserDeleted       = errors.New("user is deleted")
	ErrUserSuspended     = errors.New("user is suspended")
	ErrUserLocked        = errors.New("user is locked")
)
