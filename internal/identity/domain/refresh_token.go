package domain

import (
	"errors"
	"time"
)

type RefreshToken struct {
	ID         int64
	SessionID  int64
	TokenHash  []byte
	IssuedAt   time.Time
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	ReplacedBy *int64
	CreatedIP  *string
}

var (
	ErrRefreshTokenNotFound = errors.New("refresh token not found")
	ErrRefreshTokenRevoked  = errors.New("refresh token revoked")
	ErrRefreshTokenExpired  = errors.New("refresh token expired")
)

func NewRefreshToken(id, sessionID int64, tokenHash []byte, now, expiresAt time.Time, ip *string) (*RefreshToken, error) {
	if len(tokenHash) == 0 {
		return nil, errors.New("token hash must not be empty")
	}

	if expiresAt.Before(now) {
		return nil, errors.New("expires_at must be in the future")
	}

	return &RefreshToken{
		ID:        id,
		SessionID: sessionID,
		TokenHash: tokenHash,
		IssuedAt:  now,
		ExpiresAt: expiresAt,
		CreatedIP: ip,
	}, nil
}

func (r *RefreshToken) IsExpired(now time.Time) bool {
	return now.After(r.ExpiresAt)
}

func (r *RefreshToken) IsRevoked() bool {
	return r.RevokedAt != nil
}

func (r *RefreshToken) IsActive(now time.Time) bool {
	return !r.IsRevoked() && !r.IsExpired(now)
}

func (r *RefreshToken) Revoke(now time.Time) error {
	if r.IsRevoked() {
		return ErrRefreshTokenRevoked
	}

	r.RevokedAt = &now

	return nil
}

func (r *RefreshToken) Replace(newID int64) {
	r.ReplacedBy = &newID
}
