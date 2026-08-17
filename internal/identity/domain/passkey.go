package domain

import (
	"errors"
	"time"
)

// PasskeyChallenge is a cached WebAuthn challenge for registration/login flows.
type PasskeyChallenge struct {
	FlowID    int64     `json:"flow_id"`
	UserID    int64     `json:"user_id"`
	Challenge string    `json:"challenge"`
	Type      string    `json:"type"` // registration or login
	CreatedAt time.Time `json:"created_at"`
}

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

var (
	ErrPasskeyNotFound = errors.New("passkey not found")
	ErrPasskeyRevoked  = errors.New("passkey revoked")
)

func NewPasskey(id, userID int64, credentialID, publicKey []byte, name string, now time.Time) (*Passkey, error) {
	if len(credentialID) == 0 {
		return nil, errors.New("credential_id must not be empty")
	}

	if len(publicKey) == 0 {
		return nil, errors.New("public_key must not be empty")
	}

	if name == "" {
		return nil, errors.New("passkey name must not be empty")
	}

	return &Passkey{
		ID:           id,
		UserID:       userID,
		CredentialID: credentialID,
		PublicKey:    publicKey,
		SignCount:    0,
		Name:         name,
		CreatedAt:    now,
	}, nil
}

func (p *Passkey) IsRevoked() bool {
	return p.RevokedAt != nil
}

func (p *Passkey) Revoke(now time.Time) error {
	if p.IsRevoked() {
		return ErrPasskeyRevoked
	}

	p.RevokedAt = &now

	return nil
}

func (p *Passkey) UpdateSignCount(count int64, now time.Time) error {
	if count < p.SignCount {
		return errors.New("sign count must not decrease (possible cloned authenticator)")
	}

	p.SignCount = count
	p.LastUsedAt = &now

	return nil
}
