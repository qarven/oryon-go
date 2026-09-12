package domain

import (
	"errors"
	"time"
)

var (
	ErrIdentityNotFound = errors.New("identity not found")
)

type IdentityProvider int16

const (
	IdentityProviderUnknown   IdentityProvider = 0
	IdentityProviderGoogle    IdentityProvider = 1
	IdentityProviderApple     IdentityProvider = 2
	IdentityProviderGithub    IdentityProvider = 3
	IdentityProviderFacebook  IdentityProvider = 4
	IdentityProviderMicrosoft IdentityProvider = 5
)

func (p IdentityProvider) IsValid() bool {
	switch p {
	case IdentityProviderGoogle,
		IdentityProviderApple,
		IdentityProviderGithub,
		IdentityProviderFacebook,
		IdentityProviderMicrosoft:
		return true
	default:
		return false
	}
}

type Identity struct {
	ID              int64
	UserID          int64
	Provider        IdentityProvider
	ProviderSubject string
	CreatedAt       time.Time
	LastUsedAt      *time.Time
	RevokedAt       *time.Time
}

func (i Identity) IsRevoked() bool {
	return i.RevokedAt != nil
}
