package domain

import (
	"errors"
	"time"
)

var (
	ErrPasskeyNotFound = errors.New("passkey not found")
)

type Passkey struct {
	ID           int64
	UserID       int64
	CredentialID []byte
	PublicKey    []byte
	SignCount    int64
	Name         string
	AAGUID       *string
	Transports   []string
	DeviceType   *string
	BackedUp     bool
	CreatedAt    time.Time
	LastUsedAt   *time.Time
	RevokedAt    *time.Time
}

func (p Passkey) IsRevoked() bool {
	return p.RevokedAt != nil
}
