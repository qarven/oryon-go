package domain

import (
	"errors"
	"time"
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
	case IdentityProviderGoogle, IdentityProviderApple, IdentityProviderGithub, IdentityProviderFacebook, IdentityProviderMicrosoft:
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

var (
	ErrIdentityNotFound      = errors.New("identity not found")
	ErrIdentityAlreadyExists = errors.New("identity already exists")
	ErrIdentityRevoked       = errors.New("identity revoked")
)

func NewIdentity(id, userID int64, provider IdentityProvider, subject string, now time.Time) (*Identity, error) {
	if !provider.IsValid() {
		return nil, errors.New("invalid identity provider")
	}

	if subject == "" {
		return nil, errors.New("provider subject must not be empty")
	}

	return &Identity{
		ID:              id,
		UserID:          userID,
		Provider:        provider,
		ProviderSubject: subject,
		CreatedAt:       now,
	}, nil
}

func (i *Identity) IsRevoked() bool {
	return i.RevokedAt != nil
}

func (i *Identity) Revoke(now time.Time) error {
	if i.IsRevoked() {
		return ErrIdentityRevoked
	}

	i.RevokedAt = &now

	return nil
}

func (i *Identity) Touch(now time.Time) {
	i.LastUsedAt = &now
}

// Legacy compat: IdentityStatus kept for old code paths if needed
type IdentityStatus int16

const (
	IdentityStatusUnknown  IdentityStatus = 0
	IdentityStatusActive   IdentityStatus = 1
	IdentityStatusInactive IdentityStatus = 2
)
