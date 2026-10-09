package domain

import (
	"errors"
	"time"
)

var (
	ErrRefreshTokenNotFound = errors.New("refresh token not found")
)

type RefreshToken struct {
	ID         ID
	SessionID  ID
	TokenHash  []byte
	IssuedAt   time.Time
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	ReplacedBy *ID
	CreatedIP  *string
}

func (r RefreshToken) IsExpired(now time.Time) bool {
	return now.After(r.ExpiresAt)
}

func (r RefreshToken) IsRevoked() bool {
	return r.RevokedAt != nil
}

func (r RefreshToken) IsActive(now time.Time) bool {
	return !r.IsRevoked() && !r.IsExpired(now)
}
